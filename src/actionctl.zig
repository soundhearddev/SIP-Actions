const std = @import("std");
const sip = @import("sip");
const utils = @import("siputils");
const actions = @import("actions.zig");
const keymng = utils.keymng;
const registry = utils.registry;
const cmd = utils.cmdhandler;

fn printUsage() void {
    std.debug.print(
        \\actionctl - SIP action client
        \\
        \\  actionctl [--identity NAME] <host> <port> <action> [arg]
        \\      Actions: ping, status, reload_config, echo, metrics, peer_list, registry_lookup, whoami
        \\      If --identity is omitted, the default identity is used.
    , .{});
}

fn actionFromString(s: []const u8) ?actions.Action {
    if (std.mem.eql(u8, s, "ping")) return .ping;
    if (std.mem.eql(u8, s, "status")) return .status;
    if (std.mem.eql(u8, s, "reload_config")) return .reload_config;
    if (std.mem.eql(u8, s, "echo")) return .echo;
    if (std.mem.eql(u8, s, "metrics")) return .metrics;
    if (std.mem.eql(u8, s, "peer_list")) return .peer_list;
    if (std.mem.eql(u8, s, "registry_lookup")) return .registry_lookup;
    if (std.mem.eql(u8, s, "whoami")) return .whoami;
    return null;
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;
    const argv = try init.minimal.args.toSlice(init.arena.allocator());

    var idx: usize = 1;
    var args = cmd.ArgIter{ .argv = argv, .idx = &idx };

    var identity_name_opt: ?[]const u8 = null;
    var pos_buf: [4][]const u8 = undefined;
    var pos_count: usize = 0;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--identity")) {
            identity_name_opt = args.next() orelse {
                std.debug.print("Fehler: --identity benötigt einen Namen\n", .{});
                return error.MissingArgument;
            };
        } else if (pos_count < pos_buf.len) {
            pos_buf[pos_count] = arg;
            pos_count += 1;
        }
    }

    if (pos_count < 3) {
        printUsage();
        return error.MissingArguments;
    }

    const host = pos_buf[0];
    const port = try std.fmt.parseInt(u16, pos_buf[1], 10);
    const action_str = pos_buf[2];
    const action = actionFromString(action_str) orelse {
        std.debug.print("Unknown action: {s}\n", .{action_str});
        return error.UnknownAction;
    };

    const arg = if (pos_count > 3) pos_buf[3] else "";

    var default_buf: [64]u8 = undefined;
    const identity_name = identity_name_opt orelse
        (keymng.readDefaultIdentity(&default_buf) catch {
            std.debug.print("No identity specified and no default is set.\n", .{});
            std.debug.print("Use --identity NAME or set a default with 'setdefault NAME'.\n", .{});
            return error.NoIdentity;
        });

    var stdout_io_buf: [1024]u8 = undefined;
    var stdout_struct = std.Io.File.stdout().writer(io, &stdout_io_buf);
    const stdout_writer = &stdout_struct.interface;

    var pw_buf: [256]u8 = undefined;
    const password = try cmd.resolvePassword(io, stdout_writer, init.environ_map, .{}, &pw_buf, false);

    const client_keys = try keymng.loadIdentity(io, identity_name, password);
    const client_addr = sip.identity.baseAddress(client_keys.public);

    var hex_buf: [64]u8 = undefined;
    const hex = std.fmt.bufPrint(&hex_buf, "{x}", .{client_keys.public}) catch unreachable;
    std.debug.print("[actionctl] own identity: {s}\n", .{hex});
    std.debug.print("[actionctl] own address: {x}\n", .{client_addr});

    const resolved_host = registry.resolve(io, host) catch |err| {
        std.debug.print("Fehler beim Auflösen des Hosts '{s}': {}\n", .{ host, err });
        return error.InvalidHost;
    };

    const is_v6 = resolved_host.entry.kind == .ipv6;

    const sock = if (is_v6)
        try sip.synet.createTcpSocketFamily(std.posix.AF.INET6)
    else
        try sip.synet.createTcpSocket();
    defer sip.synet.close(sock);

    switch (resolved_host.entry.kind) {
        .ipv6 => {
            var addr6 = sip.synet.buildSockaddrIn6(resolved_host.entry.ipv6, port);
            try sip.synet.connect6(sock, &addr6);
        },
        .ipv4 => {
            var addr4 = sip.synet.buildSockaddrIn(resolved_host.entry.ipv4, port);
            try sip.synet.connect(sock, &addr4);
        },
        .mesh => {
            std.debug.print("Fehler: Mesh-Adressen werden von actionctl nicht unterstützt.\n", .{});
            return error.UnsupportedAddressKind;
        },
    }

    var disc_buf: [34]u8 = undefined;
    const disc_pkt = try sip.header.buildDiscoveryPacket(&disc_buf, client_addr, [_]u8{0} ** 16);
    try sip.synet.sendAll(sock, disc_pkt);

    var disc_reply_buf: [34]u8 = undefined;
    try sip.synet.recvExact(sock, &disc_reply_buf);

    if (disc_reply_buf[0] != sip.header.MAGIC) return error.InvalidMagic;
    if (disc_reply_buf[1] != @intFromEnum(sip.protocol.Command.discovery)) return error.InvalidDiscovery;

    var server_addr: [16]u8 = undefined;
    @memcpy(&server_addr, disc_reply_buf[2..18]);
    std.debug.print("[actionctl] discovery ok, server address: {x}\n", .{server_addr});

    var session = try sip.handshake.performKeyExchange(
        io,
        gpa,
        sock,
        client_keys,
        client_addr,
        true,
        server_addr,
    );
    defer session.deinit();

    std.debug.print("handshake ok, server={x} conn_id={x}\n", .{ session.peer_address, session.conn_id });

    // seq_num=0 ist hier sicher, weil jede Verbindung genau einen Request
    // sendet und dann geschlossen wird (siehe actiond.handleConnection).
    // Falls das je auf Connection-Reuse mit mehreren Requests umgestellt
    // wird, MUSS seq_num pro gesendetem Paket hochgezählt werden, sonst
    // wiederholt sich der aus (conn_id, seq_num) abgeleitete Nonce.
    const seq_num: u32 = 0;

    var req_buf: [512]u8 = undefined;
    const req_len = try actions.ActionRequest.build(&req_buf, action, arg);

    const wire = try sip.translation.buildOutboundPacket(
        io,
        gpa,
        client_addr,
        session.peer_address,
        session.conn_id,
        seq_num,
        .Execute,
        req_buf[0..req_len],
        session.tx,
    );
    defer gpa.free(wire);

    try sip.synet.sendAll(sock, wire);

    std.debug.print("Action '{s}' gesendet, warte auf Antwort...\n", .{action_str});

    const inbound = try sip.translation.readInboundPacket(sock, gpa, session.rx);
    defer sip.translation.freeInboundPacket(gpa, inbound);

    if (inbound.parsed.command != .Data) {
        std.debug.print("unerwartetes Antwort-Command: {}\n", .{inbound.parsed.command});
        return;
    }

    const reply = actions.ServerReply.decode(inbound.parsed.payload) catch {
        std.debug.print("ungültige Antwort vom Server\n", .{});
        return;
    };

    switch (reply) {
        .action => |resp| {
            if (resp.ok) {
                std.debug.print("OK: {s}\n", .{resp.message});
            } else {
                std.debug.print("FEHLER: {s}\n", .{resp.message});
            }
        },
        .protocol_error => |e| {
            std.debug.print("SERVERFEHLER [{s}]: {s}\n", .{ @tagName(e.code), e.message });
        },
    }
}
