const std = @import("std");
const sip = @import("sip");
const actions = @import("actions.zig");
const utils = @import("siputils");
const sipd = utils.sipd;
const keymng = utils.keymng;
const registry = utils.registry;

const Io = std.Io;

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

// Fix: fehlende strukturierte Fehlerantworten (neues Wire-Format nötig).
//
// Vorher endete jeder Fehler nach dem Handshake (kaputtes Paket, falsches
// Command, ungültiger Payload, Antwortpuffer zu klein) in einem stillen
// `return`: geloggt wurde nur serverseitig, der Client sah über
// `defer sip.synet.close(sock)` nichts weiter als ein TCP-Reset/EOF. Für
// ein CLI-Tool wie actionctl bedeutete das: jeder interne Serverfehler sah
// für den Nutzer wie "ungültige Antwort vom Server" oder ein Timeout aus,
// ganz ohne Diagnosewert.
//
// sendProtocolError nutzt die schon etablierte, verschlüsselte Session
// (die an dieser Stelle immer existiert, weil alle Aufrufer erst nach
// erfolgreichem performKeyExchange + isTrusted-Check laufen) und schickt
// eine actions.ServerReply.protocol_error zurück - dasselbe Wire-Format,
// das auch für normale Action-Antworten benutzt wird, nur mit einem
// anderen Tag. actionctl kann das jetzt strukturiert decodieren und dem
// Nutzer eine echte Fehlermeldung mit Code anzeigen statt nur zu raten.
fn sendProtocolError(
    io: std.Io,
    allocator: std.mem.Allocator,
    sock: sip.synet.Socket,
    server_addr: [16]u8,
    session: anytype,
    code: actions.ErrorCode,
    message: []const u8,
) void {
    var err_buf: [300]u8 = undefined;
    const reply = actions.ServerReply{ .protocol_error = .{ .code = code, .message = message } };
    const encoded = reply.encode(&err_buf) catch return;

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
    ) catch return;
    defer allocator.free(wire);

    sip.synet.sendAll(sock, wire) catch {};
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

    // Fix: Discovery-Reply vor Authentifizierung (Protokoll-Design).
    //
    // Vorher wurde keymng.isTrusted(disc_src) bereits hier geprüft, BEVOR
    // der Peer im Handshake beweisen musste, dass er den privaten Schlüssel
    // zu disc_src wirklich besitzt. disc_src sind nur 16 unauthentifizierte
    // Bytes aus dem Discovery-Paket - jeder konnte eine trusted Adresse
    // behaupten und bekam dafür schon eine Antwort (Bestätigung, dass der
    // Server läuft, plus server_addr), lange bevor irgendeine Kryptografie
    // geprüft wurde. Das ist ein Pre-Auth-Oracle: ein Angreifer kann allein
    // über das Discovery-Reply herausfinden, welche Adressen trusted sind,
    // ohne je einen Schlüssel zu besitzen.
    //
    // Der Fix verschiebt die Trust-Prüfung vollständig hinter den Handshake:
    // Auf ein strukturell gültiges Discovery-Paket antwortet der Server
    // jetzt immer gleich, unabhängig davon, ob disc_src trusted ist oder
    // nicht. Erst nach performKeyExchange, wenn session.peer_address
    // kryptografisch durch die Signatur des Peers bewiesen ist, wird
    // genau einmal geprüft, ob dieser (jetzt bewiesene) Peer trusted ist.
    // Ein Spoofer bekommt weiterhin nur ein generisches Discovery-Reply,
    // erfährt daraus aber nicht mehr, ob "seine" Adresse trusted ist -
    // das lässt sich erst nach einer gültigen Signatur feststellen, die
    // ein Angreifer ohne den privaten Schlüssel nicht liefern kann.
    //
    // Hinweis: Wiederholtes Senden von Discovery-Paketen mit unterschied-
    // lichen disc_src-Werten (whoami/echo-artiges Fingerprinting, wer wann
    // antwortet) ist damit noch nicht verhindert - das bräuchte zusätzlich
    // z.B. ein Rate-Limit schon auf Discovery-Ebene. Das ist laut Aufgabe
    // hier bewusst nicht mit adressiert.
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

    // Die einzige Stelle, an der Trust geprüft wird: erst hier ist
    // session.peer_address kryptografisch bewiesen (Signatur im Handshake).
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
        sendProtocolError(io, allocator, sock, server_addr, session, .malformed_packet, "failed to read request packet");
        return;
    };
    defer sip.translation.freeInboundPacket(allocator, inbound);

    if (inbound.parsed.command != .Execute) {
        std.debug.print("unexpected command: {}\n", .{inbound.parsed.command});
        sendProtocolError(io, allocator, sock, server_addr, session, .unexpected_command, "expected Execute command");
        return;
    }

    sip.protocol.validatePayload(allocator, .Execute, inbound.parsed.payload) catch |err| {
        std.debug.print("invalid payload: {}\n", .{err});
        sendProtocolError(io, allocator, sock, server_addr, session, .invalid_payload, "invalid action payload");
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
    const reply = actions.ServerReply{ .action = resp };
    const encoded = reply.encode(&resp_buf) catch {
        std.debug.print("Response too large for buffer\n", .{});
        sendProtocolError(io, allocator, sock, server_addr, session, .response_too_large, "response too large for buffer");
        return;
    };

    // seq_num=0 ist hier sicher, weil jede Verbindung genau eine Response
    // sendet und dann geschlossen wird. Falls das je auf mehrere Responses
    // pro Verbindung umgestellt wird, MUSS seq_num hochgezählt werden,
    // sonst wiederholt sich der aus (conn_id, seq_num) abgeleitete Nonce.
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

    const result = registry.resolve(io, arg) catch {
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

const AcceptContext = struct {
    gpa: std.mem.Allocator,
    server_keys: sip.identity.KeyPair,
    server_addr: [16]u8,
    identity_name: []const u8,
    rate_limiter: *actions.RateLimiter,
    audit_log: *actions.AuditLog,
    metrics: *Metrics,
    verbose: bool,
};

fn onAccept(io: std.Io, ctx: AcceptContext, conn: sip.synet.Socket) void {
    handleConnection(
        io,
        ctx.gpa,
        conn,
        ctx.server_keys,
        ctx.server_addr,
        ctx.identity_name,
        ctx.rate_limiter,
        ctx.audit_log,
        ctx.metrics,
        ctx.verbose,
    ) catch |err| {
        std.debug.print("[actiond] Verbindung fehlgeschlagen: {}\n", .{err});
    };
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;

    const argv = try init.minimal.args.toSlice(init.arena.allocator());

    var idx: usize = 1;
    var args = utils.cmdhandler.ArgIter{ .argv = argv, .idx = &idx };

    var config_path: []const u8 = sipd.CONFIG_PATH;
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--config")) {
            config_path = args.next() orelse {
                std.debug.print("Fehler: --config benötigt einen Pfad\n", .{});
                return error.MissingArgument;
            };
        }
    }

    const config = try sipd.loadConfig(io, gpa, config_path);

    var metrics = Metrics.init(@intCast(@divFloor(std.Io.Timestamp.now(io, .real).toNanoseconds(), std.time.ns_per_s)));

    const server_keys = try sipd.loadOrCreateIdentity(init, config.identity_name);
    const server_addr = sip.identity.baseAddress(server_keys.public);

    var addr_buf: [80]u8 = undefined;
    const addr_str = try sip.identity.formatSipAddress(&addr_buf, config.identity_name, server_addr);
    std.debug.print("[actiond] starte, Adresse={s}\n", .{addr_str});

    const listener = try sipd.createListener(config);
    defer sip.synet.close(listener);
    std.debug.print("[actiond] lauscht auf Port {d}\n", .{config.port});

    var rate_limit_entries: [256]actions.RateLimiter.Entry = undefined;
    var rate_limiter = actions.RateLimiter.init(&rate_limit_entries, RATE_LIMIT_MAX_PER_WINDOW, RATE_LIMIT_WINDOW_SECONDS);

    var audit_entries: [AUDIT_LOG_CAPACITY]actions.AuditEntry = undefined;
    var audit_log = actions.AuditLog.init(&audit_entries);

    const accept_ctx = AcceptContext{
        .gpa = gpa,
        .server_keys = server_keys,
        .server_addr = server_addr,
        .identity_name = config.identity_name,
        .rate_limiter = &rate_limiter,
        .audit_log = &audit_log,
        .metrics = &metrics,
        .verbose = config.verbose,
    };

    try sipd.acceptLoop(io, listener, accept_ctx, onAccept);

    std.debug.print("[actiond] heruntergefahren\n", .{});
}
