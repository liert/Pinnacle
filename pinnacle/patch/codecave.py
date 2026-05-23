"""Code cave scanning."""

from __future__ import annotations

from pinnacle.elf.binary import ElfBinary
from pinnacle.elf.address import is_executable_segment


def find_code_cave(elf: ElfBinary, size: int, fill: tuple[int, ...] = (0x00, 0xFF)) -> tuple[int, int] | None:
    size = _align4(size)
    for segment in getattr(elf.binary, "segments", []) or []:
        if not is_executable_segment(segment):
            continue
        content = bytes(getattr(segment, "content", []) or [])
        base_vaddr = int(getattr(segment, "virtual_address", 0) or 0)
        base_offset = int(getattr(segment, "file_offset", 0) or 0)
        run_start: int | None = None
        run_len = 0
        for index, byte in enumerate(content):
            if byte in fill:
                if run_start is None:
                    run_start = index
                    run_len = 0
                run_len += 1
                if run_len >= size:
                    aligned = _align4(run_start)
                    if index + 1 - aligned >= size:
                        return base_vaddr + aligned, base_offset + aligned
            else:
                run_start = None
                run_len = 0
    return None


def _align4(value: int) -> int:
    return (value + 3) & ~3
