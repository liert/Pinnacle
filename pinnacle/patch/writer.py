"""ELF patch writing helpers."""

from __future__ import annotations

from pathlib import Path

from pinnacle.elf.binary import ElfBinary


def patch_bytes(elf: ElfBinary, vaddr: int, data: bytes) -> None:
    patch_address = getattr(elf.binary, "patch_address", None)
    if callable(patch_address):
        patch_address(vaddr, list(data))
        return
    raise RuntimeError("LIEF binary object does not support patch_address()")


def write_binary(elf: ElfBinary, output_path: str | Path) -> None:
    writer = getattr(elf.binary, "write", None)
    if callable(writer):
        writer(str(output_path))
        return
    raise RuntimeError("LIEF binary object does not support write()")
