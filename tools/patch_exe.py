"""Retarget WinBox.exe kernel32.dll import to wbcompat.dll (same length)."""
from __future__ import annotations

import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXE = ROOT / "dist" / "WinBox.exe"
OLD = b"kernel32.dll"
NEW = b"wbcompat.dll"
assert len(OLD) == len(NEW) == 12


def pe_checksum(data: bytearray) -> int:
    size = len(data)
    total = 0
    i = 0
    limit = size & ~1
    while i < limit:
        total += data[i] | (data[i + 1] << 8)
        total = (total & 0xFFFF) + (total >> 16)
        i += 2
    if size & 1:
        total += data[-1]
        total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (total + size) & 0xFFFFFFFF


def rva_to_off(rva: int, sections: list) -> int | None:
    for va, size, raw in sections:
        if va <= rva < va + size:
            return raw + (rva - va)
    return None


def import_name_offsets(data: bytes | bytearray):
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    coff = e_lfanew + 4
    num_sections = struct.unpack_from("<H", data, coff + 2)[0]
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    pe32plus = magic == 0x20B
    dd_off = opt + (112 if pe32plus else 96)
    import_rva = struct.unpack_from("<I", data, dd_off + 8)[0]
    sec_off = opt + opt_size
    sections = []
    for i in range(num_sections):
        s = sec_off + i * 40
        va, vsize, raw, rawsize = struct.unpack_from("<IIII", data, s + 12)
        sections.append((va, max(vsize, rawsize), raw))
    offsets = []
    if not import_rva:
        return offsets, sections, dd_off, opt
    base = rva_to_off(import_rva, sections)
    i = 0
    while True:
        desc = data[base + i * 20 : base + i * 20 + 20]
        if len(desc) < 20 or desc == b"\0" * 20:
            break
        name_rva = struct.unpack_from("<I", desc, 12)[0]
        off = rva_to_off(name_rva, sections)
        if off is not None:
            offsets.append(off)
        i += 1
    return offsets, sections, dd_off, opt


def patch(path: Path) -> None:
    data = bytearray(path.read_bytes())
    offsets, sections, dd_off, opt = import_name_offsets(data)
    replaced = 0
    for off in offsets:
        end = data.find(b"\0", off)
        name = bytes(data[off:end])
        if name.lower() == OLD:
            if end - off != len(NEW):
                raise SystemExit("length mismatch for %r at 0x%x" % (name, off))
            data[off:end] = NEW
            replaced += 1
            print("  patched import at 0x%x: %r -> %r" % (off, name, NEW))
    if replaced == 0:
        raise SystemExit("kernel32.dll not found in import table")

    bound_off = dd_off + 11 * 8
    rva, size = struct.unpack_from("<II", data, bound_off)
    if rva or size:
        struct.pack_into("<II", data, bound_off, 0, 0)
        print("  bound import cleared")
    else:
        print("  bound import already empty")

    checksum_off = opt + 64
    struct.pack_into("<I", data, checksum_off, 0)
    struct.pack_into("<I", data, checksum_off, pe_checksum(data))
    path.write_bytes(data)
    print("  wrote %s (%s rename(s))" % (path, replaced))


def main() -> int:
    if not EXE.exists():
        print("missing %s" % EXE, file=sys.stderr)
        return 1
    bak = EXE.with_suffix(".exe.orig")
    if not bak.exists():
        bak.write_bytes(EXE.read_bytes())
        print("backup: %s" % bak)
    else:
        EXE.write_bytes(bak.read_bytes())
        print("restored from %s" % bak)
    patch(EXE)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
