# Pinnacle User Guide

Language: [中文](USER_GUIDE.md) | English

This guide is for humans using Pinnacle from a terminal.

## What Pinnacle Does

Pinnacle patches an AArch64 Linux ELF file at a chosen virtual address. It can:

- Find imported functions such as `malloc`, `fopen`, or `unlink` through PLT entries.
- Generate AArch64 calls to those functions.
- Assemble custom hook code.
- Place hook code in an executable-section code cave, or add a new executable `PT_LOAD` segment when no cave is available.

## Recommended Workflow

1. Inspect imports:

```powershell
.\.venv\Scripts\python.exe -m pinnacle.cli list-imports target.elf
```

2. Inspect local symbols:

```powershell
.\.venv\Scripts\python.exe -m pinnacle.cli list-symbols target.elf
```

3. Run a dry-run patch:

```powershell
.\.venv\Scripts\python.exe -m pinnacle.cli inject `
  --input target.elf `
  --addr 0x4294A8 `
  --asm examples\call_import_malloc.asm `
  --strategy trampoline `
  --mode raw `
  --return-mode none `
  --dry-run
```

4. If the plan looks correct, write the patched file:

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

## Important Options

- `--input`: input ELF file.
- `--output`: patched output file.
- `--addr`: virtual address to patch.
- `--call`: function name to call.
- `--prefer imported`: prefer imported PLT functions.
- `--asm`: custom assembly template.
- `--strategy trampoline`: branch from the target address to a payload.
- `--payload-placement auto`: default mode; use an executable-section code cave first, then fall back to a new executable `PT_LOAD` segment.
- `--payload-placement codecave`: only use executable-section code caves.
- `--payload-placement segment`: force a new executable `PT_LOAD` segment.
- `--mode minimal`: wrap payload with a small prologue and epilogue.
- `--mode raw`: do not wrap the payload; the assembly file is responsible for prologue and epilogue.
- `--return-mode jump`: append a branch back to the original flow.
- `--return-mode ret`: append `ret`.
- `--return-mode none`: append nothing.
- `--allow-inline-data`: allow inline data such as `.asciz` in raw payloads.
- `--dry-run`: print the patch plan without writing a file.

## Function-Shaped Hooks for IDA

If you want IDA to recognize the payload more easily, use an assembly file that starts and ends like a normal function:

```asm
stp x29, x30, [sp, #-16]!
mov x29, sp
...
ldp x29, x30, [sp], #16
ret
```

Then inject with:

```powershell
--mode raw --return-mode none
```

## Example Assembly

The repository includes:

```text
examples/call_import_malloc.asm
```

It calls the imported `malloc` function with a fixed size and returns the result in `x0`. It is intentionally generic so it can be published with the repository.

Project-specific hook payloads should stay in a local ignored directory such as `hooks/`.

## Troubleshooting

If a dependency is missing, install:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

If you do not want automatic executable-segment creation, pass an explicit executable payload address:

```powershell
--payload-addr 0x430c48
```

If `trampoline` refuses a patch, the overwritten instruction may be PC-relative. Choose a different address or use a strategy appropriate for your target.
