"""Build wbcompat.dll as a pure export-forwarder PE32+ DLL."""
from __future__ import annotations

import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMPORTS_FILE = ROOT / "tools" / "kernel32_imports.txt"
OUT_DLL = ROOT / "dist" / "wbcompat.dll"

# Symbols that must come from KernelBase on Server 2016 (not kernel32 export table).
KERNELBASE_SYMS = {
    "SetThreadDescription": "KERNELBASE.SetThreadDescription",
    "GetThreadDescription": "KERNELBASE.GetThreadDescription",
}


def align(value, a):
    return (value + a - 1) & ~(a - 1)


def u16(x):
    return struct.pack("<H", x)


def u32(x):
    return struct.pack("<I", x)


def u64(x):
    return struct.pack("<Q", x)


def pe_checksum(data):
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


def build_dll(symbols):
    section_align = 0x1000
    file_align = 0x200
    header_raw = 0x200
    image_base = 0x180000000

    # Tiny DllMain: mov eax,1; ret
    text = bytearray(b"\xB8\x01\x00\x00\x00\xC3")
    text_rva = 0x1000
    text_vsize = align(len(text), section_align)
    rdata_rva = text_rva + text_vsize

    export_names = sorted(set(symbols) | set(KERNELBASE_SYMS))

    buf = bytearray()
    pos = {}

    def mark(name):
        pos[name] = len(buf)

    def rrva(name):
        return rdata_rva + pos[name]

    def pad(n=4):
        while len(buf) % n:
            buf.append(0)

    # --- export directory first ---
    mark("export_dir")
    export_dir_off = len(buf)
    buf += b"\x00" * 40

    mark("eat")
    eat_off = len(buf)
    buf += b"\x00" * (4 * len(export_names))

    mark("name_ptrs")
    name_ptrs_off = len(buf)
    buf += b"\x00" * (4 * len(export_names))

    mark("ordinals")
    for i in range(len(export_names)):
        buf += u16(i)
    pad(4)

    mark("export_dll_name")
    buf += b"wbcompat.dll\0"
    pad(4)

    for sym in export_names:
        mark("ename_" + sym)
        buf += sym.encode("ascii") + b"\0"
    pad(4)

    for i, sym in enumerate(export_names):
        struct.pack_into("<I", buf, name_ptrs_off + i * 4, rrva("ename_" + sym))

    for i, sym in enumerate(export_names):
        if sym in KERNELBASE_SYMS:
            fwd = KERNELBASE_SYMS[sym]
        else:
            fwd = "KERNEL32." + sym
        mark("fwd_" + sym)
        struct.pack_into("<I", buf, eat_off + i * 4, rrva("fwd_" + sym))
        buf += (fwd + "\0").encode("ascii")

    mark("export_end")
    export_va = rrva("export_dir")
    export_size = pos["export_end"] - pos["export_dir"]

    ed = bytearray()
    ed += u32(0)
    ed += u32(0)
    ed += u16(0) + u16(0)
    ed += u32(rrva("export_dll_name"))
    ed += u32(1)
    ed += u32(len(export_names))
    ed += u32(len(export_names))
    ed += u32(rrva("eat"))
    ed += u32(rrva("name_ptrs"))
    ed += u32(rrva("ordinals"))
    buf[export_dir_off:export_dir_off + 40] = ed

    rdata = bytes(buf)
    rdata_vsize = align(len(rdata), section_align)
    text_raw_size = align(len(text), file_align)
    rdata_raw_size = align(len(rdata), file_align)
    text_raw = header_raw
    rdata_raw = text_raw + text_raw_size
    size_of_image = rdata_rva + rdata_vsize

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)

    pe = bytearray()
    pe += b"PE\0\0"
    pe += u16(0x8664)
    pe += u16(2)
    pe += u32(0)
    pe += u32(0)
    pe += u32(0)
    pe += u16(0xF0)
    pe += u16(0x4022)

    opt = bytearray()
    opt += u16(0x20B)
    opt += bytes([14, 0])
    opt += u32(len(text))
    opt += u32(len(rdata))
    opt += u32(0)
    opt += u32(text_rva)  # DllMain
    opt += u32(text_rva)
    opt += u64(image_base)
    opt += u32(section_align)
    opt += u32(file_align)
    opt += u16(6) + u16(0)
    opt += u16(0) + u16(0)
    opt += u16(6) + u16(0)
    opt += u32(0)
    opt += u32(size_of_image)
    opt += u32(header_raw)
    opt += u32(0)
    opt += u16(2)
    opt += u16(0x160)
    opt += u64(0x100000)
    opt += u64(0x1000)
    opt += u64(0x100000)
    opt += u64(0x1000)
    opt += u32(0)
    opt += u32(16)

    data_dirs = bytearray(16 * 8)
    struct.pack_into("<II", data_dirs, 0 * 8, export_va, export_size)
    opt += data_dirs
    assert len(opt) == 0xF0

    def sect(name, vsize, va, rawsize, rawptr, chars):
        s = bytearray(40)
        s[0:8] = name.ljust(8, b"\0")
        struct.pack_into("<I", s, 8, vsize)
        struct.pack_into("<I", s, 12, va)
        struct.pack_into("<I", s, 16, rawsize)
        struct.pack_into("<I", s, 20, rawptr)
        struct.pack_into("<I", s, 36, chars)
        return bytes(s)

    sec_text = sect(b".text", len(text), text_rva, text_raw_size, text_raw, 0x60000020)
    sec_rdata = sect(b".rdata", len(rdata), rdata_rva, rdata_raw_size, rdata_raw, 0x40000040)

    headers = bytearray()
    headers += dos
    headers += pe
    headers += opt
    headers += sec_text
    headers += sec_rdata
    if len(headers) > header_raw:
        raise SystemExit("headers too big: %s" % len(headers))
    headers.extend(b"\x00" * (header_raw - len(headers)))

    out = bytearray()
    out += headers
    out += bytes(text).ljust(text_raw_size, b"\0")
    out += rdata.ljust(rdata_raw_size, b"\0")

    checksum_off = 0x98 + 64
    struct.pack_into("<I", out, checksum_off, 0)
    struct.pack_into("<I", out, checksum_off, pe_checksum(out))
    return bytes(out)


def main():
    symbols = [
        line.strip()
        for line in IMPORTS_FILE.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if "SetThreadDescription" not in symbols:
        raise SystemExit("SetThreadDescription not in import list")
    dll = build_dll(symbols)
    OUT_DLL.parent.mkdir(parents=True, exist_ok=True)
    OUT_DLL.write_bytes(dll)
    print("Wrote %s (%s bytes)" % (OUT_DLL, len(dll)))
    print("Forward SetThreadDescription -> KERNELBASE.SetThreadDescription")


if __name__ == "__main__":
    main()
