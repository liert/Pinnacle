"""Capstone-backed disassembly helpers."""

from __future__ import annotations

from dataclasses import dataclass

from pinnacle.deps import require_capstone


@dataclass(slots=True)
class Instruction:
    address: int
    mnemonic: str
    op_str: str
    size: int

    @property
    def text(self) -> str:
        return f"{self.mnemonic} {self.op_str}".strip()


def disasm_aarch64(code: bytes, address: int) -> list[Instruction]:
    cs_mod = require_capstone()
    md = cs_mod.Cs(cs_mod.CS_ARCH_ARM64, cs_mod.CS_MODE_ARM)
    return [
        Instruction(
            address=int(insn.address),
            mnemonic=insn.mnemonic,
            op_str=insn.op_str,
            size=int(insn.size),
        )
        for insn in md.disasm(code, address)
    ]


def ensure_decodable(code: bytes, address: int) -> None:
    insns = disasm_aarch64(code, address)
    decoded = sum(insn.size for insn in insns)
    if decoded != len(code):
        raise ValueError(f"Capstone decoded {decoded} bytes, expected {len(code)}")
