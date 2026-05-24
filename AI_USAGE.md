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
.\.venv\Scripts\python.exe -m pinnacle.cli inject --input target.elf --addr 0x4294A8 --call malloc --prefer imported --strategy trampoline --dry-run
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
- `pinnacle/patch/`: patch planning, executable-section code cave scanning, executable segment insertion, writing.
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

- `--mode` is a compatibility option and should be treated as not recommended for new hook exit design.
- Default `--mode full` saves `x0-x30` and `NZCV` at payload entry into an automatically reserved runtime context buffer by extending a writable NOBITS area, usually `.bss`.
- Full context preservation only uses a temporary 16-byte stack slot for the address scratch register; it must not push the whole register frame onto the hooked function's current stack.
- Use asm exit markers: `ret`, `ret_restore`, `ret_jump 0xADDR`, `ret_restore_jump 0xADDR`.
- If no `ret...` marker exists, restore all registers and `NZCV`, then return to the original flow.
- `--return-mode none` means do not append a jump or `ret`.
- `--return-mode jump` is the default trampoline behavior.
- `--return-mode ret` appends `ret`.
- `--payload-placement auto` must avoid `.rodata`: use executable-section caves first, then add a new executable `PT_LOAD` segment.
- `--payload-placement load-cave` is the UPX-compatible mode: use existing executable `PT_LOAD` caves and do not add Program Headers.
- `--allow-inline-data` is required for raw payloads containing `.asciz` or other embedded data bytes.
- Imported calls should resolve to `CallableTarget(kind="imported", call_vaddr=<plt address>)`.
- Tests that need the local `server` fixture should skip when it is absent.
