// PE structures for export directory parsing. Used by syscall.zig to resolve SSNs.
const std = @import("std");

pub const IMAGE_DOS_HEADER = extern struct {
    e_magic: u16,
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    e_cparhdr: u16,
    e_minalloc: u16,
    e_maxalloc: u16,
    e_ss: u16,
    e_sp: u16,
    e_csum: u16,
    e_ip: u16,
    e_cs: u16,
    e_lfarlc: u16,
    e_ovno: u16,
    e_res: [4]u16,
    e_oemid: u16,
    e_oeminfo: u16,
    e_res2: [10]u16,
    e_lfanew: i32,
};

pub const IMAGE_FILE_HEADER = extern struct {
    Machine: u16,
    NumberOfSections: u16,
    TimeDateStamp: u32,
    PointerToSymbolTable: u32,
    NumberOfSymbols: u32,
    SizeOfOptionalHeader: u16,
    Characteristics: u16,
};

pub const IMAGE_DATA_DIRECTORY = extern struct {
    VirtualAddress: u32,
    Size: u32,
};

pub const IMAGE_OPTIONAL_HEADER64 = extern struct {
    Magic: u16,
    MajorLinkerVersion: u8,
    MinorLinkerVersion: u8,
    SizeOfCode: u32,
    SizeOfInitializedData: u32,
    SizeOfUninitializedData: u32,
    AddressOfEntryPoint: u32,
    BaseOfCode: u32,
    ImageBase: u64,
    SectionAlignment: u32,
    FileAlignment: u32,
    MajorOperatingSystemVersion: u16,
    MinorOperatingSystemVersion: u16,
    MajorImageVersion: u16,
    MinorImageVersion: u16,
    MajorSubsystemVersion: u16,
    MinorSubsystemVersion: u16,
    Win32VersionValue: u32,
    SizeOfImage: u32,
    SizeOfHeaders: u32,
    CheckSum: u32,
    Subsystem: u16,
    DllCharacteristics: u16,
    SizeOfStackReserve: u64,
    SizeOfStackCommit: u64,
    SizeOfHeapReserve: u64,
    SizeOfHeapCommit: u64,
    LoaderFlags: u32,
    NumberOfRvaAndSizes: u32,
    DataDirectory: [16]IMAGE_DATA_DIRECTORY,
};

pub const IMAGE_NT_HEADERS = IMAGE_NT_HEADERS64;

pub const IMAGE_NT_HEADERS64 = extern struct {
    Signature: u32,
    FileHeader: IMAGE_FILE_HEADER,
    OptionalHeader: IMAGE_OPTIONAL_HEADER64,
};

// needed for FreshyCalls table + gadget pool scan.
pub const IMAGE_SECTION_HEADER = extern struct {
    Name: [8]u8,
    VirtualSize: u32,
    VirtualAddress: u32,
    SizeOfRawData: u32,
    PointerToRawData: u32,
    PointerToRelocations: u32,
    PointerToLinenumbers: u32,
    NumberOfRelocations: u16,
    NumberOfLinenumbers: u16,
    Characteristics: u32,
};

pub const IMAGE_EXPORT_DIRECTORY = extern struct {
    Characteristics: u32,
    TimeDateStamp: u32,
    MajorVersion: u16,
    MinorVersion: u16,
    Name: u32,
    Base: u32,
    NumberOfFunctions: u32,
    NumberOfNames: u32,
    AddressOfFunctions: u32,
    AddressOfNames: u32,
    AddressOfNameOrdinals: u32,
};

// walk the export directory of a PE module, find a named export, return its address.
pub fn findExport(dll_base: [*]u8, name: []const u8) ?[*]u8 {
    const dos = @as(*const IMAGE_DOS_HEADER, @ptrCast(@alignCast(dll_base)));
    if (dos.e_magic != 0x5A4D) return null;

    const nt_hdrs = @as(*const IMAGE_NT_HEADERS64, @ptrCast(@alignCast(
        dll_base + @as(usize, @intCast(dos.e_lfanew)),
    )));
    if (nt_hdrs.Signature != 0x00004550) return null;

    const export_dir_rva = nt_hdrs.OptionalHeader.DataDirectory[0];
    if (export_dir_rva.VirtualAddress == 0) return null;

    const exp = @as(*const IMAGE_EXPORT_DIRECTORY, @ptrCast(@alignCast(
        dll_base + @as(usize, @intCast(export_dir_rva.VirtualAddress)),
    )));

    const names = @as([*]const u32, @ptrCast(@alignCast(dll_base + exp.AddressOfNames)));
    const funcs = @as([*]const u32, @ptrCast(@alignCast(dll_base + exp.AddressOfFunctions)));
    const ords = @as([*]const u16, @ptrCast(@alignCast(dll_base + exp.AddressOfNameOrdinals)));

    var i: u32 = 0;
    while (i < exp.NumberOfNames) : (i += 1) {
        const export_name_ptr = @as([*:0]const u8, @ptrCast(dll_base + names[i]));
        const export_name = std.mem.sliceTo(export_name_ptr, 0);

        if (std.mem.eql(u8, export_name, name)) {
            const rva = funcs[ords[i]];
            return dll_base + rva;
        }
    }
    return null;
}
