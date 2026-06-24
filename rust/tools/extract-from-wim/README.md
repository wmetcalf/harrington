# extract-from-wim

Pull the synthetic Windows environment data `batdeob` needs (assoc /
ftype / env / where) from a Windows install ISO, without booting Windows.

Produces a JSON snapshot in the same shape as
`rust/tools/collect-windows-env.bat`, so the two are interchangeable.

## How it works

1. `7z e ... sources/install.wim` from the ISO.
2. Parse the WIM's tail XML metadata block to list image indices and
   builds (no wimlib required).
3. `7z e` the `Windows/System32/config/{SOFTWARE,SYSTEM}` registry hives
   from the chosen image.
4. Parse the offline hives with [regipy](https://github.com/mkorman90/regipy):
   - `SOFTWARE\Classes\.ext\(default)` → `assoc`
   - `SOFTWARE\Classes\<ProgID>\shell\open\command\(default)` → `ftype`
   - `SYSTEM\<CurrentControlSet>\Control\Session Manager\Environment` → `env`
   - `SYSTEM\<CurrentControlSet>\Control\ComputerName\…` → `COMPUTERNAME`
5. Resolve a `where` map for known LOLBAS + system binaries by scanning
   the WIM file listing (prefers System32, then SysWOW64, then PATH dirs).

No registry boot, no VM, no PowerShell, no network access.

## Usage

```bash
# one-time
python3 -m venv .venv
.venv/bin/pip install regipy

# extract install.wim from the ISO (one-time, ~6 GB)
mkdir -p work
7z e -y -owork /path/to/Win11.iso sources/install.wim

# list image indices in the WIM
.venv/bin/python extract.py --wim work/install.wim --list-images

# extract data for image 6 (Win11 Pro on a typical retail Win11 ISO)
.venv/bin/python extract.py --wim work/install.wim --image 6 \
    --out data/win11.json
```

The result lives in `data/<winver>.json`. The Rust crate at
`rust/crates/batdeob-core/data/` loads whichever file matches the
`--winver` CLI flag (default `win10`) and merges it onto the Python-ported
baseline env (from `batch_deobfuscator/batch_interpreter.py:122-172`).

## What the output looks like

```jsonc
{
  "schema": "batdeob-windows-env/v1",
  "source": "extract-from-wim",
  "source_image_index": 6,
  "source_build": "26200",
  "ver": "Microsoft Windows [Version 10.0.26200]",
  "identity": { "SystemRoot": "C:\\Windows", "ComSpec": "...", ... },
  "assoc":    { ".bat": "batfile", ".cmd": "cmdfile", ... },          // 228 entries
  "ftype":    { "batfile": "\"%1\" %*", "VBSFile": "...WScript.exe \"%1\" %*", ... }, // 163 entries
  "env":      { "Path": "...", "PATHEXT": "...", "TEMP": "...", ... }, // 15 entries
  "where":    { "cmd.exe": "C:\\Windows\\System32\\cmd.exe", ... }    // 54 entries
}
```

## Known limitations

- The SYSTEM hive on an *unbooted* WIM image is sparse. Some env vars
  that real Windows populates at first boot (`USERDOMAIN`,
  `LOGONSERVER`, `ProgramData`, `ProgramFiles(x86)` if there's
  no x86 stub yet) are absent here. The runtime layer merges this
  output onto the Python-ported baseline, which fills those in.
- `where` entries that don't ship with the client SKU
  (`pwsh.exe`, `bash.exe`, `diskshadow.exe`, `msxsl.exe`, `wget.exe`,
  `tftp.exe`, `runscripthelper.exe`, `taskhost.exe`, `appvlp.exe`,
  `more.exe`, `type.com`, `at.exe`, `sqldumper.exe`) come back as
  empty strings — that's accurate, not a bug.
- Per-user file associations (`HKCU\Software\Classes`) and the modern
  `UserChoice` mechanism are not in `SOFTWARE`. We only report the
  HKLM-level defaults. This is fine for the deobfuscator's needs
  (assoc/ftype are only consulted when `for /F` scrapes `assoc|findstr X`,
  which itself only sees HKLM at the cmd.exe level).

## Differences vs. the sandbox collector

`rust/tools/collect-windows-env.bat` captures a *live* booted system, so
it gets all the OOBE-populated env vars and per-machine state. The
extract-from-wim path captures a *pristine* image — predictable,
locale-pinned, reproducible across analyst machines, no VM required.

Both produce the same schema. Prefer:
- **extract-from-wim** for CI: deterministic, no VM, ~30 seconds.
- **collect-windows-env** when you need the live state of a specific
  analyst's machine or to capture configuration drift.
