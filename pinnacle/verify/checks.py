"""Patch safety checks."""

from __future__ import annotations

from pinnacle.errors import PatchPlanningError

from .disasm import disasm_aarch64

PC_RELATIVE_MNEMONICS = {
    "adr",
    "adrp",
    "b",
    "bl",
    "b.eq",
    "b.ne",
    "b.cs",
    "b.hs",
    "b.cc",
    "b.lo",
    "b.mi",
    "b.pl",
    "b.vs",
    "b.vc",
    "b.hi",
    "b.ls",
    "b.ge",
    "b.lt",
    "b.gt",
    "b.le",
    "cbz",
    "cbnz",
    "tbz",
    "tbnz",
}


def require_aligned_aarch64(vaddr: int) -> None:
    if vaddr % 4 != 0:
        raise PatchPlanningError(f"AArch64 address must be 4-byte aligned: 0x{vaddr:x}")


def reject_pc_relative(code: bytes, address: int) -> None:
    for insn in disasm_aarch64(code, address):
        mnemonic = insn.mnemonic.lower()
        if mnemonic in PC_RELATIVE_MNEMONICS:
            raise PatchPlanningError(
                f"Refusing to relocate PC-relative instruction at 0x{insn.address:x}: {insn.text}"
            )
        if mnemonic == "ldr" and insn.op_str.lower().startswith(("x", "w")) and "[" not in insn.op_str:
            raise PatchPlanningError(
                f"Refusing to relocate possible LDR literal at 0x{insn.address:x}: {insn.text}"
            )
