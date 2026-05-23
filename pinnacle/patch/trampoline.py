"""Trampoline planning helpers."""

from __future__ import annotations

from pinnacle.asm.aarch64_call import branch_abs
from pinnacle.asm.assembler import assemble_aarch64
from pinnacle.elf.address import read_bytes_at_va
from pinnacle.elf.binary import ElfBinary
from pinnacle.verify.checks import reject_pc_relative


def entry_branch_bytes(insert_vaddr: int, payload_vaddr: int) -> tuple[str, bytes]:
    asm = branch_abs(payload_vaddr, insert_vaddr)
    return asm, assemble_aarch64(asm, insert_vaddr)


def overwritten_for_entry_branch(elf: ElfBinary, insert_vaddr: int, branch_len: int) -> bytes:
    length = ((branch_len + 3) // 4) * 4
    data = read_bytes_at_va(elf, insert_vaddr, length)
    reject_pc_relative(data, insert_vaddr)
    return data
