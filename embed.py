with open("valak.bin", "rb") as f:
    data = f.read()

lines = []
for i in range(0, len(data), 12):
    chunk = data[i:i+12]
    lines.append("    " + ", ".join(f"0x{b:02x}" for b in chunk) + ",")

with open("src/main.zig") as f:
    content = f.read()

start = content.index("const shellcode = [_]u8{")
end = content.index("};\n\nfn", start) + 3
new_block = "const shellcode = [_]u8{\n" + "\n".join(lines) + "\n};"
content = content[:start] + new_block + content[end:]

with open("src/main.zig", "w") as f:
    f.write(content)

print(f"Embedded {len(data)} bytes")
