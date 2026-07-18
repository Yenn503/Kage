# Kage <sub>影</sub>

<p align="center">
  <img src="assets/Kage.png" alt="Kage">
</p>

> 影に潜む

Shellcode loader using indirect syscalls. Self-injection, jitter between steps. Also Windowless proccess. 

## Build

```bash
# 1. place your shellcode as valak.bin in this directory
# 2. compile:
zig build -Dtarget=x86_64-windows-gnu -Doptimize=ReleaseFast
# → zig-out/bin/kage.exe
```

Single binary output, no external files needed at runtime.

## Why Zig

No CRT. C programs pull in the C Runtime Library which adds DLL imports to your IAT. Zig just calls the OS. Means less for AV to see.

Detection engines mostly know C, C++, Rust, Go. Zig flies under the radar. Lower VirusTotal scores.

Ghidra struggles with Zig binaries (there's an open bug for it). IDA doesn't properly support it either. Makes reverse engineering harder.

## 仕掛け

- **影探し** — ntdll via PEB walk (`gs:[0x60]`)
- **闇渡り** — indirect syscall dispatch
- **血判** — Hell's Gate SSN resolution
- **影纏い** — XOR-encoded asm dispatch globals

For evasion use [Valak](https://git.churchofmalware.org/JYenn/valak).

## Layout

```
src/
├── main.zig       entry, execution
├── win32.zig      types & externs
├── pe.zig         PE parser, export resolver
├── syscall.zig    Hell's Gate extraction + PEB ntdll finder
├── hells_gate.s   asm dispatch (XOR globals)
build.zig
```

## License

MIT
