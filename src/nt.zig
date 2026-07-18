// nt pseudo-handles not in std.os.windows.
const windows = @import("std").os.windows;

// from phnt: NtCurrentProcess = (HANDLE)-1, NtCurrentThread = (HANDLE)-2
pub const NtCurrentProcess: windows.HANDLE = @ptrFromInt(@as(usize, @bitCast(@as(i64, -1))));
pub const NtCurrentThread: windows.HANDLE = @ptrFromInt(@as(usize, @bitCast(@as(i64, -2))));

pub inline fn NT_SUCCESS(status: windows.NTSTATUS) bool {
    return @intFromEnum(status) >= 0;
}
