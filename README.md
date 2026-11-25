# WinBox 4 on Windows Server 2016

MikroTik WinBox 4 (Qt 6.10) does not start on **Windows Server 2016** / Windows 10 **1607** (build `10.0.14393`). MikroTik’s position is that support will not be added:

> WinBox 4 relies on Qt 6.10, which dropped support for Windows Server 2016.

This repository provides a **compatibility shim** so the official WinBox 4 Windows binary can load and run on Server 2016 without rebuilding Qt or WinBox.

Verified on Windows Server 2016 (`10.0.14393`) with WinBox **4.5** — process stays up with main window title `WinBox 4.5`.

---

## Problem

Stock `WinBox.exe` is a large statically linked Qt app. Its PE import table pulls `SetThreadDescription` from `kernel32.dll`.

On Windows 10 1607 / Server 2016 that API is **not** exported by `kernel32.dll`. It is only available via runtime lookup from `KernelBase.dll` (Microsoft documents this explicitly). The Windows loader therefore fails **before** `main` with:

```text
The procedure entry point SetThreadDescription could not be located
in the dynamic link library ...\WinBox.exe
```

Qt upstream can avoid this with `QT_WIN_SERVER_2016_COMPAT` (dynamic `GetProcAddress` on KernelBase). MikroTik’s public build does not enable that. We cannot recompile WinBox (no source), and dropping a fake `kernel32.dll` next to the EXE does nothing because `kernel32` is a **Known DLL**.

---

## Solution

```text
WinBox.exe  --(import)-->  wbcompat.dll  --(forward)-->  KERNEL32.*
                                         --(forward)-->  KERNELBASE.SetThreadDescription
```

1. **`wbcompat.dll`** — a tiny PE32+ DLL generated in pure Python (no MSVC/MinGW required). It re-exports every `kernel32` symbol that WinBox imports as `KERNEL32.Name` forwarders, except:
   - `SetThreadDescription` → `KERNELBASE.SetThreadDescription`
   - `GetThreadDescription` → `KERNELBASE.GetThreadDescription`
2. **Import rename** — in a *copy* of `WinBox.exe`, the import DLL name `KERNEL32.dll` (12 bytes) is rewritten to `wbcompat.dll` (same length). Bound Import directory is cleared if present; PE checksum is updated.
3. **`qt.conf`** (optional hardening) — forces `fontengine=gdi` to reduce “tofu” / blank glyph issues seen with DirectWrite on 1607-class systems.

A pristine backup is kept as `dist/WinBox.exe.orig`.

---

## Requirements

- Windows x64 (intended target: Server 2016 / Win10 1607; also works on newer Windows)
- Python **3.8+** (tested with 3.13)
- Network access once, to download the official WinBox zip from MikroTik (or place `WinBox.exe` in `dist/` yourself)

This project does **not** redistribute MikroTik binaries. You must obtain WinBox from MikroTik.

---

## Usage

```bat
git clone https://github.com/MrAriaNet/winbox4-patch.git
cd Winbox
python tools\prepare.py
dist\WinBox.exe
```

What `prepare.py` does:

1. Downloads [WinBox_Windows.zip 4.5](https://download.mikrotik.com/routeros/winbox/4.5/WinBox_Windows.zip) into `dist/` if needed (TLS 1.2)
2. Scans the EXE import table and lists symbols missing on the current OS
3. Builds `dist/wbcompat.dll`
4. Patches `dist/WinBox.exe` (after saving `WinBox.exe.orig`)
5. Writes `dist/qt.conf`

### Manual steps (equivalent)

```bat
:: 1) Put official WinBox.exe (+ assets) into dist\
:: 2) Generate import list + DLL + patch
python tools\scan_imports.py
python tools\build_wbcompat.py
python tools\patch_exe.py
```

`scan_imports.py` alone is useful to confirm what is missing on a given OS before patching.

---

## Repository layout

```text
README.md
UNLICENSE
.gitignore
tools/
  prepare.py          # end-to-end: download → build → patch
  scan_imports.py     # PE import scanner vs live OS exports
  build_wbcompat.py   # PE forwarder DLL generator (no C toolchain)
  patch_exe.py        # rename KERNEL32.dll import → wbcompat.dll
dist/                 # created at runtime (gitignored)
  WinBox.exe          # patched copy
  WinBox.exe.orig     # untouched official binary
  wbcompat.dll
  qt.conf
  assets/             # from MikroTik zip
```

---

## Technical notes

### Why a forwarder DLL?

- Known DLLs (`kernel32`, `user32`, …) cannot be overridden by a same-named file beside the EXE.
- Changing the import name to a private DLL of equal string length is a stable, reversible PE edit.
- Export forwarders are resolved by the Windows loader; no trampoline code is required for `SetThreadDescription`.

### What was scanned on Server 2016

Against WinBox 4.5, **193** `kernel32` imports were checked. The only missing export was:

| DLL           | Symbol                 |
|---------------|------------------------|
| `kernel32.dll`| `SetThreadDescription` |

DPI-related `user32` APIs used by WinBox (`SetProcessDpiAwarenessContext`, `GetDpiForWindow`, …) are present on 14393. `UiaRaiseNotificationEvent` is missing from the system `UIAutomationCore.dll` but is not a static import that blocks process start in this build.

### Safety / scope

- Does not crack, license-bypass, or reverse-engineer RouterOS protocols.
- Only retargets one import DLL name and supplies a forwarder.
- Re-run `prepare.py` after upgrading WinBox; keep using an official zip from MikroTik.
- Antivirus may flag PE-patched EXEs; the backup `.orig` and open tooling are intentional for auditability.

### Limitations

- Unofficial / unsupported by MikroTik and The Qt Company.
- Future WinBox builds might import additional APIs missing on 1607; re-run `scan_imports.py` and extend `KERNELBASE_SYMS` (or similar) in `build_wbcompat.py` if needed.
- Font rendering on Server 2016 can still look worse than on 1809+; `qt.conf` helps but is not a full DirectWrite replacement.

---

## License

The tooling in this repository is released under [The Unlicense](LICENSE).

**WinBox**, **RouterOS**, and related names are trademarks of MikroTik. Obtain and use WinBox under MikroTik’s terms. Do not commit or publish MikroTik binaries in this repo (`dist/` is gitignored for that reason).