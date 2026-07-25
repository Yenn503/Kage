// nt pseudo-handles + win32 constants not in std.os.windows.
const windows = @import("std").os.windows;

//--------------------------------------------------------> PSEUDO-HANDLES
// from phnt: NtCurrentProcess = (HANDLE)-1, NtCurrentThread = (HANDLE)-2
pub const NtCurrentProcess: windows.HANDLE = @ptrFromInt(@as(usize, @bitCast(@as(i64, -1))));
pub const NtCurrentThread: windows.HANDLE = @ptrFromInt(@as(usize, @bitCast(@as(i64, -2))));

//--------------------------------------------------------> MEMORY PROTECTION CONSTANTS
pub const MEM_COMMIT = 0x00001000;
pub const MEM_RESERVE = 0x00002000;
pub const PAGE_READWRITE = 0x04;
pub const PAGE_EXECUTE_READ = 0x20;

// success = NTSTATUS high bit clear (non-negative i32)
pub inline fn NT_SUCCESS(status: windows.NTSTATUS) bool {
    return @as(i32, @bitCast(@intFromEnum(status))) >= 0;
}
