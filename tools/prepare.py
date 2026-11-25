"""Download WinBox 4, build wbcompat.dll, and patch the import table."""
from __future__ import annotations

import ssl
import subprocess
import sys
import zipfile
from pathlib import Path
from urllib.request import Request, urlopen

TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent
DIST = ROOT / "dist"
ZIP_URL = "https://download.mikrotik.com/routeros/winbox/4.5/WinBox_Windows.zip"
ZIP_PATH = DIST / "WinBox_Windows.zip"


def run(script: str) -> None:
    print("==>", script)
    subprocess.check_call([sys.executable, str(TOOLS / script)])


def download(url: str, dest: Path) -> None:
    print("Downloading", url)
    ctx = ssl.create_default_context()
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    except Exception:
        pass
    req = Request(url, headers={"User-Agent": "WinBox-2016-compat"})
    with urlopen(req, context=ctx) as resp:
        dest.write_bytes(resp.read())
    print("Saved", dest, "(%s bytes)" % dest.stat().st_size)


def ensure_winbox() -> None:
    DIST.mkdir(parents=True, exist_ok=True)
    exe = DIST / "WinBox.exe"
    orig = DIST / "WinBox.exe.orig"
    if orig.exists() or exe.exists():
        return
    download(ZIP_URL, ZIP_PATH)
    with zipfile.ZipFile(ZIP_PATH) as zf:
        zf.extractall(DIST)
    print("Extracted to", DIST)


def main() -> int:
    ensure_winbox()
    orig = DIST / "WinBox.exe.orig"
    exe = DIST / "WinBox.exe"
    scan_target = orig if orig.exists() else exe

    sys.path.insert(0, str(TOOLS))
    from scan_imports import parse_imports

    imports, _ = parse_imports(scan_target.read_bytes())
    syms = imports.get("kernel32.dll") or imports.get("wbcompat.dll") or []
    if not syms and orig.exists():
        imports, _ = parse_imports(orig.read_bytes())
        syms = imports.get("kernel32.dll", [])

    (TOOLS / "kernel32_imports.txt").write_text("\n".join(syms) + "\n", encoding="utf-8")
    print("kernel32 imports:", len(syms))

    import ctypes
    from ctypes import wintypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.LoadLibraryW.argtypes = [wintypes.LPCWSTR]
    k32.LoadLibraryW.restype = wintypes.HMODULE
    k32.GetProcAddress.argtypes = [wintypes.HMODULE, wintypes.LPCSTR]
    k32.GetProcAddress.restype = ctypes.c_void_p
    h = k32.LoadLibraryW("kernel32.dll")
    missing = [s for s in syms if not k32.GetProcAddress(h, s.encode("ascii"))]
    print("missing on this OS:", missing or "none")

    run("build_wbcompat.py")
    run("patch_exe.py")
    (DIST / "qt.conf").write_text(
        "[Platforms]\nWindowsArguments = fontengine=gdi\n", encoding="ascii"
    )
    print("Ready:", DIST / "WinBox.exe", "+", DIST / "wbcompat.dll")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
