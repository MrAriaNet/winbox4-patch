"""Scan PE imports of WinBox.exe against this OS's DLL exports."""
from __future__ import annotations

import ctypes
import struct
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXE = ROOT / "dist" / "WinBox.exe"
KNOWN_DLLS = {
    "kernel32.dll",
    "ntdll.dll",
    "user32.dll",
    "gdi32.dll",
    "advapi32.dll",
    "shell32.dll",
    "ole32.dll",
    "oleaut32.dll",
    "comdlg32.dll",
    "comctl32.dll",
    "ws2_32.dll",
    "rpcrt4.dll",
    "secur32.dll",
    "shlwapi.dll",
    "imm32.dll",
    "version.dll",
    "winmm.dll",
}


def rva_to_off(rva: int, sections: list[tuple[int, int, int]]) -> int | None:
    for va, size, raw in sections:
        if va <= rva < va + size:
            return raw + (rva - va)
    return None


def parse_imports(data: bytes) -> dict[str, list[str]]:
    if data[:2] != b"MZ":
        raise SystemExit("not a PE")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        raise SystemExit("bad PE signature")
    coff = e_lfanew + 4
    num_sections = struct.unpack_from("<H", data, coff + 2)[0]
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    pe32plus = magic == 0x20B
    dd_off = opt + (112 if pe32plus else 96)
    import_rva, import_size = struct.unpack_from("<II", data, dd_off + 8)
    bound_rva, bound_size = struct.unpack_from("<II", data, dd_off + 11 * 8)
    delay_rva, delay_size = struct.unpack_from("<II", data, dd_off + 13 * 8)

    sec_off = opt + opt_size
    sections: list[tuple[int, int, int]] = []
    for i in range(num_sections):
        s = sec_off + i * 40
        va, vsize, raw, rawsize = struct.unpack_from("<IIII", data, s + 12)
        sections.append((va, max(vsize, rawsize), raw))

    def read_cstr(rva: int) -> str:
        off = rva_to_off(rva, sections)
        if off is None:
            return ""
        end = data.find(b"\0", off)
        return data[off:end].decode("ascii", "replace")

    imports: dict[str, list[str]] = defaultdict(list)

    def walk_thunks(dll: str, thunk_rva: int) -> None:
        off = rva_to_off(thunk_rva, sections)
        if off is None:
            return
        entry_size = 8 if pe32plus else 4
        ordinal_bit = 1 << (63 if pe32plus else 31)
        i = 0
        while True:
            raw = data[off + i * entry_size : off + i * entry_size + entry_size]
            if len(raw) < entry_size:
                break
            val = struct.unpack("<Q" if pe32plus else "<I", raw)[0]
            if val == 0:
                break
            if val & ordinal_bit:
                imports[dll].append(f"#{val & 0xFFFF}")
            else:
                hint_rva = val & (0x7FFFFFFF if not pe32plus else 0x7FFFFFFFFFFFFFFF)
                name_off = rva_to_off(hint_rva, sections)
                if name_off is not None:
                    end = data.find(b"\0", name_off + 2)
                    imports[dll].append(data[name_off + 2 : end].decode("ascii", "replace"))
            i += 1

    # IMAGE_IMPORT_DESCRIPTOR
    if import_rva:
        base = rva_to_off(import_rva, sections)
        if base is not None:
            i = 0
            while True:
                desc = data[base + i * 20 : base + i * 20 + 20]
                if len(desc) < 20 or desc == b"\0" * 20:
                    break
                ilt, _, __, name_rva, iat = struct.unpack_from("<IIIII", desc)
                dll = read_cstr(name_rva).lower()
                walk_thunks(dll, ilt or iat)
                i += 1

    # Delay import (IMAGE_DELAYLOAD_DESCRIPTOR)
    if delay_rva:
        base = rva_to_off(delay_rva, sections)
        if base is not None:
            i = 0
            while True:
                desc = data[base + i * 32 : base + i * 32 + 32]
                if len(desc) < 32 or desc == b"\0" * 32:
                    break
                attrs, name_rva, _, name_table, __, ___, ____, _____ = struct.unpack_from(
                    "<IIIIIIII", desc
                )
                dll = read_cstr(name_rva).lower()
                walk_thunks(dll, name_table)
                i += 1

    return dict(imports), {
        "pe32plus": pe32plus,
        "bound_rva": bound_rva,
        "bound_size": bound_size,
        "import_rva": import_rva,
        "sections": sections,
        "dd_off": dd_off,
        "e_lfanew": e_lfanew,
    }


def resolve_ok(dll: str, symbol: str) -> bool:
    if symbol.startswith("#"):
        return True  # ordinal; assume present
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.LoadLibraryW.argtypes = [ctypes.c_wchar_p]
    k32.LoadLibraryW.restype = ctypes.c_void_p
    k32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    k32.GetProcAddress.restype = ctypes.c_void_p
    h = k32.LoadLibraryW(dll)
    if not h:
        # try system32 path
        h = k32.LoadLibraryW(rf"C:\Windows\System32\{dll}")
    if not h:
        return False
    return bool(k32.GetProcAddress(h, symbol.encode("ascii")))


def main() -> int:
    data = EXE.read_bytes()
    imports, meta = parse_imports(data)
    print(f"PE32+: {meta['pe32plus']}")
    print(f"Bound Import RVA/Size: {meta['bound_rva']:#x}/{meta['bound_size']}")
    print(f"DLLs imported: {len(imports)}")
    missing: dict[str, list[str]] = {}
    for dll, syms in sorted(imports.items()):
        bad = [s for s in syms if not resolve_ok(dll, s)]
        known = dll.lower() in KNOWN_DLLS
        print(f"\n{dll} ({len(syms)} symbols) known={known}")
        if bad:
            missing[dll] = bad
            for s in bad:
                print(f"  MISSING: {s}")
        else:
            print("  OK")
    print("\n=== SUMMARY MISSING ===")
    if not missing:
        print("none")
    else:
        for dll, syms in missing.items():
            print(f"{dll}: {', '.join(syms)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
