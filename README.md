# Mirage

Zig-based x86_64 Windows shellcode loader using indirect syscalls and fresh ntdll mapping for userland EDR evasion.

## Build

Requires Zig 0.16.0.

```bash
zig build
# output: zig-out/bin/loader.exe
```

## Usage

Run `loader.exe` on Windows x86_64. The loader:

1. Maps a clean `ntdll.dll` from `\KnownDlls`
2. Resolves SSNs and gadgets from the fresh copy via Hell's Gate
3. Patches `AmsiScanBuffer` and `EtwEventWrite` through indirect syscalls
4. Allocates RW memory → copies XOR-encoded shellcode → decodes → protects to RX
5. Creates a thread at shellcode entry point via indirect syscalls

## Project Structure

```
src/
├── main.zig       Entry point, patches, shellcode execution chain
├── win32.zig      Windows type aliases, structs, @extern declarations
├── pe.zig         PE parser, export table resolver
├── fresh.zig      Fresh ntdll loader via NtOpenSection + NtMapViewOfSection
├── syscall.zig    Hell's Gate SSN and gadget extraction
├── hells_gate.s   x86_64 asm: XOR-encoded indirect syscall dispatch
build.zig
```

## Credits

Assembly dispatch pattern derived from [zcircuit](https://github.com/Hiroki6/zcircuit).

## License

MIT
