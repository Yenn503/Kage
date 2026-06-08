const std = @import("std");

pub const DWORD = u32;
pub const ULONG = u32;
pub const ULONG_PTR = usize;
pub const SIZE_T = usize;
pub const BOOL = i32;
pub const HANDLE = *anyopaque;
pub const HMODULE = *anyopaque;
pub const WORD = u16;
pub const BYTE = u8;
pub const BOOLEAN = u8;
pub const LPCSTR = [*:0]const u8;
pub const NTSTATUS = i32;
pub const ACCESS_MASK = u32;
pub const LARGE_INTEGER = extern struct {
    QuadPart: i64,
};

pub const PAGE_EXECUTE_READWRITE: ULONG = 0x40;

pub inline fn NT_SUCCESS(status: NTSTATUS) bool {
    return status >= 0;
}

pub const NtCurrentProcess: HANDLE = @ptrFromInt(@as(usize, @bitCast(@as(i64, -1))));

pub const MEM_COMMIT: ULONG = 0x00001000;
pub const MEM_RESERVE: ULONG = 0x00002000;

pub const PAGE_NOACCESS: ULONG = 0x01;
pub const PAGE_READONLY: ULONG = 0x02;
pub const PAGE_READWRITE: ULONG = 0x04;
pub const PAGE_EXECUTE: ULONG = 0x10;
pub const PAGE_EXECUTE_READ: ULONG = 0x20;

pub const OBJ_CASE_INSENSITIVE: ULONG = 0x00000040;

pub const SECTION_MAP_EXECUTE: ULONG = 0x0008;
pub const SECTION_MAP_READ: ULONG = 0x0004;
pub const SECTION_QUERY: ULONG = 0x0001;

pub const THREAD_ALL_ACCESS: ULONG = 0x001F03FF;

pub const UNICODE_STRING = extern struct {
    Length: u16,
    MaximumLength: u16,
    Buffer: [*]u16,
};

pub const OBJECT_ATTRIBUTES = extern struct {
    Length: ULONG,
    RootDirectory: ?HANDLE,
    ObjectName: *const UNICODE_STRING,
    Attributes: ULONG,
    SecurityDescriptor: ?*anyopaque,
    SecurityQualityOfService: ?*anyopaque,
};

pub const SECTION_INHERIT = enum(ULONG) {
    ViewShare = 1,
    ViewUnmap = 2,
};

const wincc: std.builtin.CallingConvention = .{ .x86_64_win = .{} };

pub fn initObjectAttributes(name: *const UNICODE_STRING, attrs: ULONG, root: ?HANDLE) OBJECT_ATTRIBUTES {
    return OBJECT_ATTRIBUTES{
        .Length = @sizeOf(OBJECT_ATTRIBUTES),
        .RootDirectory = root,
        .ObjectName = name,
        .Attributes = attrs,
        .SecurityDescriptor = null,
        .SecurityQualityOfService = null,
    };
}

pub const kernel32 = struct {
    pub const LoadLibraryA = @extern(*const fn (lpLibFileName: LPCSTR) callconv(wincc) ?HMODULE, .{
        .name = "LoadLibraryA",
        .library_name = "kernel32",
    });

    pub const GetProcAddress = @extern(*const fn (hModule: HMODULE, lpProcName: LPCSTR) callconv(wincc) ?*anyopaque, .{
        .name = "GetProcAddress",
        .library_name = "kernel32",
    });

    pub const GetModuleHandleA = @extern(*const fn (lpModuleName: LPCSTR) callconv(wincc) ?HMODULE, .{
        .name = "GetModuleHandleA",
        .library_name = "kernel32",
    });

};

pub const ntdll = struct {
    pub const NtMapViewOfSection = @extern(*const fn (sectionHandle: HANDLE, processHandle: HANDLE, baseAddress: *?*anyopaque, zeroBits: ULONG_PTR, commitSize: SIZE_T, sectionOffset: ?*LARGE_INTEGER, viewSize: *SIZE_T, inheritDisposition: ULONG, allocationType: ULONG, pageProtection: ULONG) callconv(wincc) NTSTATUS, .{
        .name = "NtMapViewOfSection",
        .library_name = "ntdll",
    });

    pub const NtOpenSection = @extern(*const fn (sectionHandle: *HANDLE, desiredAccess: ACCESS_MASK, objectAttributes: *OBJECT_ATTRIBUTES) callconv(wincc) NTSTATUS, .{
        .name = "NtOpenSection",
        .library_name = "ntdll",
    });

    pub const NtClose = @extern(*const fn (handle: HANDLE) callconv(wincc) NTSTATUS, .{
        .name = "NtClose",
        .library_name = "ntdll",
    });
};
