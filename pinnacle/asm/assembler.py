"""Keystone assembler wrapper."""

from __future__ import annotations

from pinnacle.deps import require_keystone


def assemble_aarch64(asm: str, address: int = 0) -> bytes:
    ks_mod = require_keystone()
    ks = ks_mod.Ks(ks_mod.KS_ARCH_ARM64, ks_mod.KS_MODE_LITTLE_ENDIAN)
    encoding, _ = ks.asm(asm, addr=address)
    return bytes(encoding)
