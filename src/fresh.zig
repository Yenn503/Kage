const win = @import("win32.zig");

pub fn loadFreshNtdll() ?[*]u8 {
    var path_buf: [128]u16 = undefined;
    const path = "\\KnownDlls\\ntdll.dll";

    for (path, 0..) |ch, i| path_buf[i] = ch;
    path_buf[path.len] = 0;

    const name = win.UNICODE_STRING{
        .Length = @as(u16, @intCast(path.len * 2)),
        .MaximumLength = @as(u16, @intCast(path_buf.len * 2)),
        .Buffer = &path_buf,
    };
    var oa = win.initObjectAttributes(&name, win.OBJ_CASE_INSENSITIVE, null);

    var section_handle: win.HANDLE = undefined;
    var status = win.ntdll.NtOpenSection(
        &section_handle,
        win.SECTION_MAP_READ | win.SECTION_MAP_EXECUTE | win.SECTION_QUERY,
        &oa,
    );
    if (!win.NT_SUCCESS(status)) return null;

    var base_addr: ?*anyopaque = null;
    var view_size: win.SIZE_T = 0;
    status = win.ntdll.NtMapViewOfSection(
        section_handle,
        win.NtCurrentProcess,
        &base_addr,
        0,
        0,
        null,
        &view_size,
        @intFromEnum(win.SECTION_INHERIT.ViewUnmap),
        0,
        win.PAGE_READONLY,
    );
    _ = win.ntdll.NtClose(section_handle);
    if (!win.NT_SUCCESS(status)) return null;

    return @as([*]u8, @ptrCast(base_addr));
}
