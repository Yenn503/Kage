pub const HANDLE = *anyopaque;
pub const NTSTATUS = i32;
pub const ULONG = u32;
pub const ULONG_PTR = usize;
pub const ACCESS_MASK = u32;
pub const SIZE_T = usize;
pub const OBJECT_ATTRIBUTES = extern struct { Length: ULONG, RootDirectory: ?HANDLE, ObjectName: *anyopaque, Attributes: ULONG, SecurityDescriptor: ?*anyopaque, SecurityQualityOfService: ?*anyopaque };

pub const MEM_COMMIT: ULONG = 0x00001000;
pub const MEM_RESERVE: ULONG = 0x00002000;
pub const PAGE_READWRITE: ULONG = 0x04;
pub const PAGE_EXECUTE_READ: ULONG = 0x20;
pub const THREAD_ALL_ACCESS: ACCESS_MASK = 0x1FFFFF;
pub const NtCurrentProcess: HANDLE = @ptrFromInt(@as(usize, @bitCast(@as(i64, -1))));
pub const LARGE_INTEGER = extern struct { QuadPart: i64 };

pub inline fn NT_SUCCESS(status: NTSTATUS) bool {
    return status >= 0;
}
