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

    pub fn resolve() ?Syscalls {
        const ntdll = findNtdll() orelse return null;
        const names = [_][]const u8{
            "NtAllocateVirtualMemory",
            "NtProtectVirtualMemory",
            "NtCreateThreadEx",
            "NtWaitForSingleObject",
            "NtDelayExecution",
        };
        var result: Syscalls = undefined;
        inline for (names) |name| {
            const entry = extractEntry(ntdll, name) orelse return null;
            @field(result, name) = entry;
        }
        return result;
    }
};

fn findNtdll() ?[*]u8 {
    var peb: usize = undefined;
    asm volatile ("movq %%gs:0x60, %[r]"
        : [r] "=r" (peb),
    );
    const ldr = @as(*align(1) usize, @ptrFromInt(peb + 0x18)).*;
    const head = ldr + 0x10;
    var entry = @as(*align(1) usize, @ptrFromInt(head)).*;
    while (entry != head) : (entry = @as(*align(1) usize, @ptrFromInt(entry)).*) {
        const base = @as(*align(1) usize, @ptrFromInt(entry + 0x30)).*;
        if (base == 0) continue;
        const dos = @as(*align(1) extern struct { pad: [0x3C]u8, e_lfanew: u32 }, @ptrFromInt(base));
        const nt = @as(*align(1) extern struct {
            Signature: u32,
            FileHeader: extern struct { Machine: u16, NumberOfSections: u16, pad: [16]u8 },
            OptionalHeader: extern struct { Magic: u16, pad: [110]u8, DataDirectory: [16]extern struct { VirtualAddress: u32, Size: u32 } },
        }, @ptrFromInt(base + @as(usize, @intCast(dos.e_lfanew))));
        if (nt.Signature != 0x00004550) continue;
        const exp_dir = nt.OptionalHeader.DataDirectory[0];
        if (exp_dir.VirtualAddress == 0) continue;
        const exp = @as(*align(1) extern struct { Characteristics: u32, pad: [8]u8, Name: u32, pad2: [40]u8 }, @ptrFromInt(base + @as(usize, @intCast(exp_dir.VirtualAddress))));
        const name = @as([*:0]const u8, @ptrFromInt(base + @as(usize, @intCast(exp.Name))));
        if (std.mem.eql(u8, std.mem.sliceTo(name, 0), "ntdll.dll")) return @ptrFromInt(base);
    }
    return null;
}

fn extractEntry(ntdll: [*]u8, name: []const u8) ?Entry {
    const addr = pe.findExport(ntdll, name) orelse return null;
    const bytes = @as([*]u8, @ptrCast(addr));

    if (bytes[0] != 0x4C or bytes[1] != 0x8B or bytes[2] != 0xD1) return null;
    if (bytes[3] != 0xB8) return null;
    const number = std.mem.readInt(u32, bytes[4..8], .little);

    var gadget: ?*anyopaque = null;
    var i: usize = 0;
    while (i < 64) : (i += 1) {
        if (bytes[i] == 0x0F and bytes[i + 1] == 0x05 and bytes[i + 2] == 0xC3) {
            gadget = @ptrFromInt(@intFromPtr(addr) + i);
            break;
        }
    }
    if (gadget == null) return null;

    return Entry{ .number = number, .gadget = gadget.? };
}
