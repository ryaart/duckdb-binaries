"""Build a universal (fat) Mach-O from thin Mach-O files, like `lipo -create`."""
import struct, sys

out, *inputs = sys.argv[1:]
ALIGN = 14  # 16 KiB, as lipo uses for arm64
slices = []
for path in inputs:
    data = open(path, "rb").read()
    cputype, cpusubtype = struct.unpack("<ii", data[4:12])  # thin files are little-endian
    slices.append((cputype, cpusubtype, data))

header = struct.pack(">II", 0xCAFEBABE, len(slices))
offset = 1 << ALIGN
entries, body = b"", b""
for cputype, cpusubtype, data in slices:
    entries += struct.pack(">iiIII", cputype, cpusubtype, offset, len(data), ALIGN)
    pad = (1 << ALIGN) - (len(data) % (1 << ALIGN))
    body += data + b"\0" * pad
    offset += len(data) + pad
head = header + entries
open(out, "wb").write(head + b"\0" * ((1 << ALIGN) - len(head)) + body)
