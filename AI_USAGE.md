# AI Usage Notes

This document gives concise project instructions for coding agents.

## Project Purpose

Pinnacle is a Python CLI for AArch64 Linux ELF call injection. It uses:

- LIEF for ELF parsing, symbols, relocations, PLT/GOT, and writing.
- Keystone for AArch64 assembly.
- Capstone for disassembly and validation.

Do not replace LIEF with a handwritten ELF parser unless a narrow unsupported case requires it.

## Key Commands

```powershell
.\.venv\Scripts\python.exe -m pinnacle.cli list-imports target.elf
.\.venv\Scripts\python.exe -m pinnacle.cli list-symbols target.elf
.\.venv\Scripts\python.exe -m pinnacle.cli inject --input target.elf --addr 0x4294A8 --call malloc --prefer imported --strategy trampoline --mode minimal --dry-run
```

Custom function-shaped hook:

```powershell
.\.venv\Scripts\python.exe -m pinnacle.cli inject --input target.elf --output target.patched --addr 0x4294A8 --asm examples\call_import_malloc.asm --strategy trampoline --mode raw --return-mode none
```

Run tests:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

## Important Files

- `pinnacle/cli.py`: CLI entrypoint.
- `pinnacle/model.py`: shared dataclasses and literal modes.
- `pinnacle/elf/`: LIEF-backed ELF helpers.
- `pinnacle/asm/`: AArch64 call generation, template expansion, Keystone wrapper.
- `pinnacle/patch/`: patch planning, code cave scanning, writing.
- `pinnacle/verify/`: Capstone disassembly and safety checks.
- `examples/call_import_malloc.asm`: publishable raw function-shaped hook example.

## Repository Hygiene

Do not commit:

- `.venv/`
- `server`
- `server.patched*`
- `hooks/`
- IDA databases such as `*.id0`, `*.id1`, `*.id2`, `*.nam`, `*.til`
- `docs/aarch64_elf_asm_injection_dev_plan.md`

The public repository intentionally excludes the private development plan and local test binary.

## Implementation Notes

- `--mode raw` means the user assembly owns prologue and epilogue.
- `--return-mode none` means do not append a jump or `ret`.
- `--return-mode jump` is the default trampoline behavior.
- `--return-mode ret` appends `ret`.
- `--allow-inline-data` is required for raw payloads containing `.asciz` or other embedded data bytes.
- Imported calls should resolve to `CallableTarget(kind="imported", call_vaddr=<plt address>)`.
- Tests that need the local `server` fixture should skip when it is absent.
