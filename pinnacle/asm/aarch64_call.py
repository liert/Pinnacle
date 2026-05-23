"""AArch64 call and branch sequence generation."""

from __future__ import annotations

from pinnacle.model import SaveMode

BL_RANGE = 128 * 1024 * 1024


def can_branch_imm26(from_vaddr: int, to_vaddr: int) -> bool:
    delta = to_vaddr - from_vaddr
    return delta % 4 == 0 and -BL_RANGE <= delta < BL_RANGE


def load_abs(reg: str, value: int) -> str:
    parts = [
        f"movz {reg}, #{value & 0xffff}",
        f"movk {reg}, #{(value >> 16) & 0xffff}, lsl #16",
        f"movk {reg}, #{(value >> 32) & 0xffff}, lsl #32",
        f"movk {reg}, #{(value >> 48) & 0xffff}, lsl #48",
    ]
    return "\n".join(parts)


def call_abs(target_vaddr: int, callsite_vaddr: int | None = None, scratch: str = "x16") -> str:
    if callsite_vaddr is not None and can_branch_imm26(callsite_vaddr, target_vaddr):
        return f"bl 0x{target_vaddr:x}"
    return f"{load_abs(scratch, target_vaddr)}\nblr {scratch}"


def branch_abs(target_vaddr: int, branch_vaddr: int | None = None, scratch: str = "x16") -> str:
    if branch_vaddr is not None and can_branch_imm26(branch_vaddr, target_vaddr):
        return f"b 0x{target_vaddr:x}"
    return f"{load_abs(scratch, target_vaddr)}\nbr {scratch}"


def wrap_payload(body_asm: str, mode: SaveMode = "safe") -> str:
    body = body_asm.strip()
    if mode == "raw":
        return body
    if mode == "minimal":
        return "\n".join(
            [
                "stp x29, x30, [sp, #-16]!",
                "mov x29, sp",
                body,
                "ldp x29, x30, [sp], #16",
            ]
        )

    save = [
        "stp x29, x30, [sp, #-16]!",
        "mov x29, sp",
        "stp x0, x1, [sp, #-16]!",
        "stp x2, x3, [sp, #-16]!",
        "stp x4, x5, [sp, #-16]!",
        "stp x6, x7, [sp, #-16]!",
        "stp x8, x9, [sp, #-16]!",
        "stp x10, x11, [sp, #-16]!",
        "stp x12, x13, [sp, #-16]!",
        "stp x14, x15, [sp, #-16]!",
        "stp x16, x17, [sp, #-16]!",
        "str x18, [sp, #-16]!",
    ]
    restore = [
        "ldr x18, [sp], #16",
        "ldp x16, x17, [sp], #16",
        "ldp x14, x15, [sp], #16",
        "ldp x12, x13, [sp], #16",
        "ldp x10, x11, [sp], #16",
        "ldp x8, x9, [sp], #16",
        "ldp x6, x7, [sp], #16",
        "ldp x4, x5, [sp], #16",
        "ldp x2, x3, [sp], #16",
        "ldp x0, x1, [sp], #16",
        "ldp x29, x30, [sp], #16",
    ]
    return "\n".join([*save, body, *restore])
