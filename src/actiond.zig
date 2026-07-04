const std = @import("std");
const sip = @import("sip");
const actions = @import("actions.zig");
const utils = @import("siputils");
const keymng = utils.keymng;
const registry = utils.registry;

const Io = std.Io;

fn loadServerIdentity(io: std.Io, gpa: std.mem.Allocator, identity_name: []const u8) !sip.identity.KeyPair {
    const prompt_msg = try std.fmt.allocPrint(gpa, "[{s}] Passwort", .{identity_name});
    defer gpa.free(prompt_msg);
    const password = try promptPassword(gpa, prompt_msg);
    defer gpa.free(password);
    return keymng.loadIdentity(io, identity_name, password);
}

fn promptPassword(allocator: std.mem.Allocator, prompt_text: []const u8) ![]u8 {
    std.debug.print("{s}: ", .{prompt_text});
    const fd = std.posix.STDIN_FILENO;
    const original_termios = try std.posix.tcgetattr(fd);
    var no_echo_termios = original_termios;
    no_echo_termios.lflag.ECHO = false;
    no_echo_termios.lflag.ECHONL = false;
    try std.posix.tcsetattr(fd, .NOW, no_echo_termios);
    defer {
        std.posix.tcsetattr(fd, .NOW, original_termios) catch {};
        std.debug.print("\n", .{});
    }
    var buf: [1024]u8 = undefined;
    const n = try std.posix.read(fd, &buf);
    var len = n;
    if (len > 0 and buf[len - 1] == '\n') len -= 1;
    if (len > 0 and buf[len - 1] == '\r') len -= 1;
    const password = try allocator.alloc(u8, len);
    @memcpy(password, buf[0..len]);
    return password;
}

const RATE_LIMIT_MAX_PER_WINDOW: u32 = 30;
const RATE_LIMIT_WINDOW_SECONDS: i64 = 60;
const AUDIT_LOG_CAPACITY: usize = 128;

const DispatchContext = struct {
    identity_name: []const u8,
    server_addr: [16]u8,
    peer_addr: [16]u8,
    known_peer_count: usize,
    metrics: *Metrics,
    io: std.Io,
};

const Metrics = struct {
    start_time: i64,
    total_connections: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    untrusted_dropped: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    actions_executed: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    rate_limited: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    fn init(start_time: i64) Metrics {
        return .{ .start_time = start_time };
    }
};

fn dispatch(buf: []u8, action: actions.Action, arg: []const u8, ctx: DispatchContext) actions.ActionResponse {
    return switch (action) {
        .ping => .{ .ok = true, .message = "pong" },
        .status => buildStatusResponse(buf, ctx),
        .reload_config => .{ .ok = true, .message = "config reloaded" },
        .shutdown => .{ .ok = false, .message = "shutdown not permitted" },
        .echo => .{ .ok = true, .message = arg },
        .metrics => buildMetricsResponse(buf, ctx),
        .peer_list => buildPeerListResponse(buf, ctx),
        .registry_lookup => buildRegistryLookupResponse(buf, ctx.io, arg),
        .whoami => buildWhoamiResponse(buf, ctx),
        _ => .{ .ok = false, .message = "unknown action" },
    };
}

fn handleActionPayload(
    payload: []const u8,
    perms: actions.PermissionSet,
    rate_limiter: *actions.RateLimiter,
    audit_log: *actions.AuditLog,
    now: i64,
    ctx: DispatchContext,
    resp_buf: []u8,
) actions.ActionResponse {
    const req = actions.ActionRequest.parse(payload) catch {
        return .{ .ok = false, .message = "malformed request" };
    };

    if (!rate_limiter.allow(ctx.peer_addr, now)) {
        _ = ctx.metrics.rate_limited.fetchAdd(1, .monotonic);
        audit_log.record(ctx.peer_addr, req.action, now, false);
        return .{ .ok = false, .message = "rate limited" };
    }

    actions.isAuthorized(perms, req.action) catch |err| {
        audit_log.record(ctx.peer_addr, req.action, now, false);
        return .{ .ok = false, .message = @errorName(err) };
    };

    const resp = dispatch(resp_buf, req.action, req.arg, ctx);
    _ = ctx.metrics.actions_executed.fetchAdd(1, .monotonic);
    audit_log.record(ctx.peer_addr, req.action, now, resp.ok);
    return resp;
}

fn handleConnection(
    io: std.Io,
    allocator: std.mem.Allocator,
    sock: sip.synet.Socket,
    server_keys: sip.identity.KeyPair,
    server_addr: [16]u8,
    identity_name: []const u8,
    rate_limiter: *actions.RateLimiter,
    audit_log: *actions.AuditLog,
    metrics: *Metrics,
    verbose: bool,
) !void {
    defer sip.synet.close(sock);

    var disc_buf: [34]u8 = undefined;
    sip.synet.recvExact(sock, &disc_buf) catch return;

    if (disc_buf[0] != sip.header.MAGIC) return;
    if (disc_buf[1] != @intFromEnum(sip.protocol.Command.discovery)) return;

    var disc_src: [16]u8 = undefined;
    @memcpy(&disc_src, disc_buf[2..18]);

    if (!keymng.isTrusted(io, disc_src)) {
        _ = metrics.untrusted_dropped.fetchAdd(1, .monotonic);
        if (verbose) {
            std.debug.print("[actiond] dropped at discovery, claimed addr={x}\n", .{disc_src});
        }
        return;
    }

    var disc_reply_buf: [34]u8 = undefined;
    const disc_reply = sip.header.buildDiscoveryPacket(&disc_reply_buf, server_addr, disc_src) catch return;
    sip.synet.sendAll(sock, disc_reply) catch return;

    var session = try sip.handshake.performKeyExchange(
        io,
        allocator,
        sock,
        server_keys,
        server_addr,
        false,
        disc_src,
    );
    defer session.deinit();

    if (!keymng.isTrusted(io, session.peer_address)) {
        _ = metrics.untrusted_dropped.fetchAdd(1, .monotonic);
        if (verbose) {
            std.debug.print("[actiond] dropped untrusted peer, addr={x}\n", .{session.peer_address});
        }
        return;
    }

    if (verbose) {
        std.debug.print("handshake ok, peer={x} conn_id={x}\n", .{ session.peer_address, session.conn_id });
    }

    const inbound = sip.translation.readInboundPacket(sock, allocator, session.rx) catch |err| {
        std.debug.print("Error reading packet: {}\n", .{err});
        return;
    };
    defer sip.translation.freeInboundPacket(allocator, inbound);

    if (inbound.parsed.command != .Execute) {
        std.debug.print("unexpected command: {}\n", .{inbound.parsed.command});
        return;
    }

    sip.protocol.validatePayload(allocator, .Execute, inbound.parsed.payload) catch |err| {
        std.debug.print("invalid payload: {}\n", .{err});
        return;
    };

    const perms = actions.PermissionSet.default_safe;

    var dispatch_buf: [400]u8 = undefined;
    const ctx = DispatchContext{
        .identity_name = identity_name,
        .server_addr = server_addr,
        .peer_addr = session.peer_address,
        .known_peer_count = 1,
        .metrics = metrics,
        .io = io,
    };

    _ = ctx.metrics.total_connections.fetchAdd(1, .monotonic);

    const now: i64 = @intCast(@divFloor(std.Io.Timestamp.now(io, .real).toNanoseconds(), std.time.ns_per_s));

    const resp = handleActionPayload(
        inbound.parsed.payload,
        perms,
        rate_limiter,
        audit_log,
        now,
        ctx,
        &dispatch_buf,
    );

    var resp_buf: [512]u8 = undefined;
    const encoded = resp.encode(&resp_buf) catch {
        std.debug.print("Response too large for buffer\n", .{});
        return;
    };

    const wire = sip.translation.buildOutboundPacket(
        io,
        allocator,
        server_addr,
        session.peer_address,
        session.conn_id,
        0,
        .Data,
        encoded,
        session.tx,
    ) catch |err| {
        std.debug.print("Error building response: {}\n", .{err});
        return;
    };
    defer allocator.free(wire);

    sip.synet.sendAll(sock, wire) catch |err| {
        std.debug.print("Error sending response: {}\n", .{err});
        return;
    };
}

fn getIdentityPassword(gpa: std.mem.Allocator, identity_name: []const u8) ![]u8 {
    var env_buf: [64]u8 = undefined;
    const env_name = std.fmt.bufPrint(&env_buf, "ACTIOND_PASSWORD_{s}", .{identity_name}) catch identity_name;

    if (std.process.getEnvVarOwned(gpa, env_name)) |val| {
        return val;
    } else |_| {}

    const prompt_msg = try std.fmt.allocPrint(gpa, "[{s}] Passwort", .{identity_name});
    defer gpa.free(prompt_msg);
    return promptPassword(gpa, prompt_msg);
}

fn buildWhoamiResponse(buf: []u8, ctx: DispatchContext) actions.ActionResponse {
    const msg = std.fmt.bufPrint(buf,
        \\{{"identity":"{s}","address":"{x}"}}
    , .{ ctx.identity_name, ctx.server_addr }) catch return .{ .ok = false, .message = "buffer too small" };
    return .{ .ok = true, .message = msg };
}

fn buildMetricsResponse(buf: []u8, ctx: DispatchContext) actions.ActionResponse {
    const now: i64 = @intCast(@divFloor(std.Io.Timestamp.now(ctx.io, .real).toNanoseconds(), std.time.ns_per_s));
    const uptime = now - ctx.metrics.start_time;
    const msg = std.fmt.bufPrint(buf,
        \\{{"uptime_seconds":{d},"total_connections":{d},"actions_executed":{d},"untrusted_dropped":{d},"rate_limited":{d},"known_peers":{d}}}
    , .{
        uptime,
        ctx.metrics.total_connections.load(.monotonic),
        ctx.metrics.actions_executed.load(.monotonic),
        ctx.metrics.untrusted_dropped.load(.monotonic),
        ctx.metrics.rate_limited.load(.monotonic),
        ctx.known_peer_count,
    }) catch return .{ .ok = false, .message = "buffer too small" };
    return .{ .ok = true, .message = msg };
}

fn buildStatusResponse(buf: []u8, ctx: DispatchContext) actions.ActionResponse {
    const now: i64 = @intCast(@divFloor(std.Io.Timestamp.now(ctx.io, .real).toNanoseconds(), std.time.ns_per_s));
    const uptime = now - ctx.metrics.start_time;
    const msg = std.fmt.bufPrint(buf,
        \\{{"status":"running","identity":"{s}","uptime_seconds":{d},"known_peers":{d}}}
    , .{ ctx.identity_name, uptime, ctx.known_peer_count }) catch return .{ .ok = false, .message = "buffer too small" };
    return .{ .ok = true, .message = msg };
}

fn buildPeerListResponse(buf: []u8, ctx: DispatchContext) actions.ActionResponse {
    const msg = std.fmt.bufPrint(buf,
        \\{{"peers":["{x}"]}}
    , .{ctx.peer_addr}) catch return .{ .ok = false, .message = "buffer too small" };
    return .{ .ok = true, .message = msg };
}

fn buildRegistryLookupResponse(buf: []u8, io: std.Io, arg: []const u8) actions.ActionResponse {
    if (arg.len == 0) return .{ .ok = false, .message = "missing name arg" };

    const result = registry.resolve(io, undefined, arg) catch {
        return .{ .ok = false, .message = "not found" };
    };

    switch (result.entry.kind) {
        .ipv4 => {
            const msg = std.fmt.bufPrint(buf,
                \\{{"kind":"ipv4","addr":"{d}.{d}.{d}.{d}"}}
            , .{ result.entry.ipv4[0], result.entry.ipv4[1], result.entry.ipv4[2], result.entry.ipv4[3] }) catch
                return .{ .ok = false, .message = "buffer too small" };
            return .{ .ok = true, .message = msg };
        },
        .ipv6 => {
            var ip_buf: [40]u8 = undefined;
            const ip_str = registry.formatIpv6(&ip_buf, result.entry.ipv6);
            const msg = std.fmt.bufPrint(buf,
                \\{{"kind":"ipv6","addr":"{s}"}}
            , .{ip_str}) catch return .{ .ok = false, .message = "buffer too small" };
            return .{ .ok = true, .message = msg };
        },
        .mesh => {
            const msg = std.fmt.bufPrint(buf,
                \\{{"kind":"mesh","addr":"{x}"}}
            , .{result.entry.mesh}) catch return .{ .ok = false, .message = "buffer too small" };
            return .{ .ok = true, .message = msg };
        },
    }
}

fn setReuseAddr(sock: sip.synet.Socket) void {
    const val: c_int = 1;
    const rc = std.os.linux.setsockopt(
        sock,
        std.os.linux.SOL.SOCKET,
        std.os.linux.SO.REUSEADDR,
        std.mem.asBytes(&val),
        @sizeOf(c_int),
    );
    if (rc != 0) {
        std.debug.print("Warning: failed to set SO_REUSEADDR\n", .{});
    }
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;

    const argv = try init.minimal.args.toSlice(init.arena.allocator());

    var metrics = Metrics.init(@intCast(@divFloor(std.Io.Timestamp.now(io, .real).toNanoseconds(), std.time.ns_per_s)));

    var identity_name: []const u8 = "default";
    {
        var i: usize = 1;
        while (i < argv.len) : (i += 1) {
            if (std.mem.eql(u8, argv[i], "--identity") and i + 1 < argv.len) {
                i += 1;
                identity_name = argv[i];
            }
        }
    }

    const server_keys = try loadServerIdentity(io, gpa, identity_name);
    const server_addr = sip.identity.baseAddress(server_keys.public);

    var addr_buf: [80]u8 = undefined;
    const addr_str = try sip.identity.formatSipAddress(&addr_buf, identity_name, server_addr);
    std.debug.print("actiond starting, address={s}\n", .{addr_str});

    const listen_sock = try sip.synet.createTcpSocket();
    defer sip.synet.close(listen_sock);

    setReuseAddr(listen_sock);

    const port: u16 = 4433;
    var sockaddr = sip.synet.buildSockaddrIn(.{ 0, 0, 0, 0 }, port);
    try sip.synet.bind(listen_sock, &sockaddr);
    try sip.synet.listen(listen_sock, 16);
    std.debug.print("actiond is listening on port {d}\n", .{port});

    var rate_limit_entries: [256]actions.RateLimiter.Entry = undefined;
    var rate_limiter = actions.RateLimiter.init(&rate_limit_entries, RATE_LIMIT_MAX_PER_WINDOW, RATE_LIMIT_WINDOW_SECONDS);

    var audit_entries: [AUDIT_LOG_CAPACITY]actions.AuditEntry = undefined;
    var audit_log = actions.AuditLog.init(&audit_entries);

    while (true) {
        const client_sock = sip.synet.accept(listen_sock) catch |err| {
            std.debug.print("Connection failed: {}\n", .{err});
            continue;
        };

        handleConnection(io, gpa, client_sock, server_keys, server_addr, identity_name, &rate_limiter, &audit_log, &metrics, true) catch |err| {
            std.debug.print("accept failed: {}\n", .{err});
        };
    }
}
