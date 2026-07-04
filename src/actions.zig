const std = @import("std");

pub const Action = enum(u8) {
    ping = 0x01,
    status = 0x02,
    reload_config = 0x03,
    shutdown = 0x04,
    echo = 0x05,
    metrics = 0x06,
    peer_list = 0x07,
    registry_lookup = 0x08,
    whoami = 0x09,
    _,
};

pub const ACTION_REQUEST_VERSION: u8 = 1;

pub const ActionError = error{
    UnknownAction,
    NotAuthorized,
    MalformedRequest,
    RateLimited,
} || std.mem.Allocator.Error;

pub const ActionRequest = struct {
    version: u8,
    action: Action,
    arg: []const u8,

    const FIXED_HEADER_LEN = 2;

    pub fn build(out: []u8, action: Action, arg: []const u8) !usize {
        if (arg.len > 255) return ActionError.MalformedRequest;
        if (out.len < FIXED_HEADER_LEN + arg.len) return ActionError.MalformedRequest;

        var w: usize = 0;
        out[w] = ACTION_REQUEST_VERSION;
        w += 1;
        out[w] = @intFromEnum(action);
        w += 1;
        @memcpy(out[w..][0..arg.len], arg);
        w += arg.len;

        return w;
    }

    pub fn parse(payload: []const u8) ActionError!ActionRequest {
        if (payload.len < FIXED_HEADER_LEN) return ActionError.MalformedRequest;

        return ActionRequest{
            .version = payload[0],
            .action = @enumFromInt(payload[1]),
            .arg = payload[FIXED_HEADER_LEN..],
        };
    }
};

pub const ActionResponse = struct {
    ok: bool,
    message: []const u8,

    pub fn encode(self: ActionResponse, out: []u8) ![]u8 {
        if (out.len < 3 + self.message.len) return error.BufferTooSmall;
        out[0] = if (self.ok) 1 else 0;
        std.mem.writeInt(u16, out[1..3], @intCast(self.message.len), .big);
        @memcpy(out[3..][0..self.message.len], self.message);
        return out[0 .. 3 + self.message.len];
    }

    pub fn decode(data: []const u8) !ActionResponse {
        if (data.len < 3) return error.MalformedResponse;
        const ok = data[0] == 1;
        const msg_len = std.mem.readInt(u16, data[1..3], .big);
        if (3 + msg_len != data.len) return error.MalformedResponse;
        return .{ .ok = ok, .message = data[3..] };
    }
};

pub const Permission = enum(u16) {
    ping = 1 << 0,
    status = 1 << 1,
    reload_config = 1 << 2,
    shutdown = 1 << 3,
    echo = 1 << 4,
    metrics = 1 << 5,
    peer_list = 1 << 6,
    registry_lookup = 1 << 7,
    whoami = 1 << 8,
};

pub const PermissionSet = struct {
    bits: u16,

    pub const default_safe: PermissionSet = .{
        .bits = @intFromEnum(Permission.ping) |
            @intFromEnum(Permission.status) |
            @intFromEnum(Permission.reload_config) |
            @intFromEnum(Permission.echo) |
            @intFromEnum(Permission.metrics) |
            @intFromEnum(Permission.peer_list) |
            @intFromEnum(Permission.registry_lookup) |
            @intFromEnum(Permission.whoami),
    };

    pub const all: PermissionSet = .{ .bits = 0xFFFF };
    pub const none: PermissionSet = .{ .bits = 0 };

    pub fn has(self: PermissionSet, perm: Permission) bool {
        return (self.bits & @intFromEnum(perm)) != 0;
    }
};

fn permissionForAction(action: Action) ?Permission {
    return switch (action) {
        .ping => .ping,
        .status => .status,
        .reload_config => .reload_config,
        .shutdown => .shutdown,
        .echo => .echo,
        .metrics => .metrics,
        .peer_list => .peer_list,
        .registry_lookup => .registry_lookup,
        .whoami => .whoami,
        _ => null,
    };
}

pub fn isAuthorized(perms: PermissionSet, action: Action) ActionError!void {
    const perm = permissionForAction(action) orelse return ActionError.UnknownAction;
    if (!perms.has(perm)) return ActionError.NotAuthorized;
}

pub const RateLimiter = struct {
    pub const Entry = struct {
        addr: [16]u8,
        window_start: i64,
        count: u32,
        used: bool = false,
    };

    entries: []Entry,
    max_per_window: u32,
    window_seconds: i64,

    pub fn init(buf: []Entry, max_per_window: u32, window_seconds: i64) RateLimiter {
        for (buf) |*e| e.used = false;
        return .{ .entries = buf, .max_per_window = max_per_window, .window_seconds = window_seconds };
    }

    pub fn allow(self: *RateLimiter, addr: [16]u8, now: i64) bool {
        var free_slot: ?usize = null;

        for (self.entries, 0..) |*e, i| {
            if (!e.used) {
                if (free_slot == null) free_slot = i;
                continue;
            }
            if (!std.mem.eql(u8, &e.addr, &addr)) continue;

            if (now - e.window_start >= self.window_seconds) {
                e.window_start = now;
                e.count = 1;
                return true;
            }

            if (e.count >= self.max_per_window) return false;
            e.count += 1;
            return true;
        }

        const slot = free_slot orelse 0;
        self.entries[slot] = .{ .addr = addr, .window_start = now, .count = 1, .used = true };
        return true;
    }
};

pub const AuditEntry = struct {
    addr: [16]u8,
    action: Action,
    timestamp: i64,
    ok: bool,
};

pub const AuditLog = struct {
    entries: []AuditEntry,
    next: usize = 0,
    filled: usize = 0,

    pub fn init(buf: []AuditEntry) AuditLog {
        return .{ .entries = buf, .next = 0, .filled = 0 };
    }

    pub fn record(self: *AuditLog, addr: [16]u8, action: Action, timestamp: i64, ok: bool) void {
        self.entries[self.next] = .{ .addr = addr, .action = action, .timestamp = timestamp, .ok = ok };
        self.next = (self.next + 1) % self.entries.len;
        if (self.filled < self.entries.len) self.filled += 1;
    }

    pub fn forEachRecent(self: *const AuditLog, comptime Context: type, ctx: Context, comptime callback: fn (ctx: Context, entry: AuditEntry) void) void {
        var i: usize = 0;
        while (i < self.filled) : (i += 1) {
            const idx = (self.next + self.entries.len - 1 - i) % self.entries.len;
            callback(ctx, self.entries[idx]);
        }
    }
};

const testing = std.testing;

test "ActionRequest build/parse roundtrip ohne arg" {
    var buf: [16]u8 = undefined;
    const len = try ActionRequest.build(&buf, .ping, "");
    const req = try ActionRequest.parse(buf[0..len]);

    try testing.expectEqual(Action.ping, req.action);
    try testing.expectEqual(@as(usize, 0), req.arg.len);
}

test "ActionRequest build/parse roundtrip mit arg" {
    var buf: [64]u8 = undefined;
    const len = try ActionRequest.build(&buf, .echo, "hallo welt");
    const req = try ActionRequest.parse(buf[0..len]);

    try testing.expectEqual(Action.echo, req.action);
    try testing.expectEqualSlices(u8, "hallo welt", req.arg);
}

test "ActionRequest parse lehnt zu kurzen Payload ab" {
    const too_short = [_]u8{0x01};
    try testing.expectError(ActionError.MalformedRequest, ActionRequest.parse(&too_short));
}

test "isAuthorized: default_safe erlaubt ping, verbietet shutdown" {
    try isAuthorized(PermissionSet.default_safe, .ping);
    try testing.expectError(ActionError.NotAuthorized, isAuthorized(PermissionSet.default_safe, .shutdown));
}

test "isAuthorized: none verbietet alles" {
    try testing.expectError(ActionError.NotAuthorized, isAuthorized(PermissionSet.none, .ping));
    try testing.expectError(ActionError.NotAuthorized, isAuthorized(PermissionSet.none, .whoami));
}

test "isAuthorized: all erlaubt auch shutdown" {
    try isAuthorized(PermissionSet.all, .shutdown);
}

test "ActionResponse encode/decode roundtrip" {
    const resp = ActionResponse{ .ok = true, .message = "pong" };
    var buf: [64]u8 = undefined;
    const encoded = try resp.encode(&buf);
    const decoded = try ActionResponse.decode(encoded);
    try testing.expect(decoded.ok);
    try testing.expectEqualSlices(u8, "pong", decoded.message);
}

test "RateLimiter erlaubt bis zum Limit, dann nicht mehr" {
    var buf: [4]RateLimiter.Entry = undefined;
    var limiter = RateLimiter.init(&buf, 3, 60);
    const addr = [_]u8{0x01} ** 16;

    try testing.expect(limiter.allow(addr, 1000));
    try testing.expect(limiter.allow(addr, 1001));
    try testing.expect(limiter.allow(addr, 1002));
    try testing.expect(!limiter.allow(addr, 1003));
}

test "RateLimiter setzt Fenster nach Ablauf zurueck" {
    var buf: [4]RateLimiter.Entry = undefined;
    var limiter = RateLimiter.init(&buf, 1, 60);
    const addr = [_]u8{0x02} ** 16;

    try testing.expect(limiter.allow(addr, 1000));
    try testing.expect(!limiter.allow(addr, 1010));
    try testing.expect(limiter.allow(addr, 1061));
}

test "RateLimiter behandelt verschiedene Peers unabhaengig" {
    var buf: [4]RateLimiter.Entry = undefined;
    var limiter = RateLimiter.init(&buf, 1, 60);
    const addr_a = [_]u8{0xAA} ** 16;
    const addr_b = [_]u8{0xBB} ** 16;

    try testing.expect(limiter.allow(addr_a, 1000));
    try testing.expect(limiter.allow(addr_b, 1000));
    try testing.expect(!limiter.allow(addr_a, 1000));
    try testing.expect(!limiter.allow(addr_b, 1000));
}

test "AuditLog zeichnet Eintraege auf und liefert sie neueste zuerst" {
    var buf: [4]AuditEntry = undefined;
    var log = AuditLog.init(&buf);
    const addr = [_]u8{0x01} ** 16;

    log.record(addr, .ping, 1000, true);
    log.record(addr, .shutdown, 1001, false);

    const Collector = struct {
        seen: *std.ArrayList(Action),
        fn cb(ctx: @This(), entry: AuditEntry) void {
            ctx.seen.append(std.testing.allocator, entry.action) catch unreachable;
        }
    };
    var seen = std.ArrayList(Action).empty;
    defer seen.deinit(std.testing.allocator);

    log.forEachRecent(Collector, .{ .seen = &seen }, Collector.cb);

    try testing.expectEqual(@as(usize, 2), seen.items.len);
    try testing.expectEqual(Action.shutdown, seen.items[0]);
    try testing.expectEqual(Action.ping, seen.items[1]);
}

test "AuditLog ueberschreibt aeltesten Eintrag bei voller Kapazitaet" {
    var buf: [2]AuditEntry = undefined;
    var log = AuditLog.init(&buf);
    const addr = [_]u8{0x01} ** 16;

    log.record(addr, .ping, 1000, true);
    log.record(addr, .status, 1001, true);
    log.record(addr, .whoami, 1002, true);

    const Collector = struct {
        seen: *std.ArrayList(Action),
        fn cb(ctx: @This(), entry: AuditEntry) void {
            ctx.seen.append(std.testing.allocator, entry.action) catch unreachable;
        }
    };
    var seen = std.ArrayList(Action).empty;
    defer seen.deinit(std.testing.allocator);

    log.forEachRecent(Collector, .{ .seen = &seen }, Collector.cb);

    try testing.expectEqual(@as(usize, 2), seen.items.len);
    try testing.expectEqual(Action.whoami, seen.items[0]);
    try testing.expectEqual(Action.status, seen.items[1]);
}
