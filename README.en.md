# Pinnacle

Language: [中文](README.md) | English

Pinnacle is a Python toolkit for planning and applying AArch64 ELF call-injection patches. It resolves existing functions from ELF symbols and imported PLT entries, assembles AArch64 payloads, and patches a target address using overwrite or trampoline strategies.

The tool runs on Windows and Linux. The first supported target format is AArch64 Linux ELF.

## Features

- LIEF-based ELF parsing and writing.
- Imported function resolution through PLT entries.
- AArch64 assembly with Keystone.
- Patch verification with Capstone.
- User assembly templates with helper pseudo-instructions.
- Trampoline patches with code-cave payload placement.

## Install

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

On Linux/macOS shells:

```bash
python3 -m venv .venv
./.venv/bin/python -m pip install -r requirements.txt
```

## Basic Usage

List imported PLT functions:

```powershell
.\.venv\Scripts\python.exe -m pinnacle.cli list-imports target.elf
```

List defined function symbols:

```powershell
.\.venv\Scripts\python.exe -m pinnacle.cli list-symbols target.elf
```

Plan a patch without writing a file:

```powershell
.\.venv\Scripts\python.exe -m pinnacle.cli inject `
  --input target.elf `
  --addr 0x4294A8 `
  --call malloc `
  --prefer imported `
  --strategy trampoline `
  --mode minimal `
  --dry-run
```

Write a patched ELF:

```powershell
.\.venv\Scripts\python.exe -m pinnacle.cli inject `
  --input target.elf `
  --output target.patched `
  --addr 0x4294A8 `
  --call malloc `
  --prefer imported `
  --strategy trampoline `
  --mode minimal
```

## Custom Assembly

Pass a template file with `--asm`:

```powershell
.\.venv\Scripts\python.exe -m pinnacle.cli inject `
  --input target.elf `
  --output target.patched `
  --addr 0x4294A8 `
  --asm examples\call_import_malloc.asm `
  --strategy trampoline `
  --mode raw `
  --return-mode none
```

Supported pseudo-instructions:

```asm
call_symbol malloc
call_import malloc
load_symbol_addr x16, malloc
branch_abs 0x402e4c
```

`--mode raw` lets the assembly file provide its own function prologue and epilogue. `--return-mode none` prevents Pinnacle from appending a jump or `ret`.

If the assembly contains inline data such as `.asciz`, pass `--allow-inline-data` so validation does not require the data bytes to disassemble as instructions.

## Notes

- Use `--dry-run` first to inspect generated `entry_patch_asm` and `payload_asm`.
- External tools such as `objdump`, `readelf`, and `qemu-aarch64` are optional and are not required at runtime.
- Local test binaries and private development planning documents are intentionally excluded from the public repository.

See [USER_GUIDE.en.md](USER_GUIDE.en.md) for human-oriented usage details and [AI_USAGE.md](AI_USAGE.md) for concise agent-facing instructions.
