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


def add_executable_segment(elf: ElfBinary, content: bytes) -> tuple[int, int]:
    import lief

    segment = lief.ELF.Segment()
    segment.type = lief.ELF.Segment.TYPE.LOAD
    segment.flags = lief.ELF.Segment.FLAGS.R | lief.ELF.Segment.FLAGS.X
    segment.alignment = 0x1000
    segment.content = list(content)
    added = elf.binary.add(segment, int(getattr(elf.binary, "next_virtual_address", 0) or 0))
    return int(added.virtual_address), int(added.file_offset)
