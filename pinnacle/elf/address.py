"""Virtual-address and file-offset helpers."""

from __future__ import annotations

from typing import Any

from pinnacle.errors import PatchPlanningError

from .binary import ElfBinary, enum_name


def va_to_offset(elf: ElfBinary, vaddr: int) -> int:
    converter = getattr(elf.binary, "virtual_address_to_offset", None)
    if callable(converter):
        try:
            offset = converter(vaddr)
            if offset is not None and int(offset) >= 0:
                return int(offset)
        except Exception:
            pass

    for segment in getattr(elf.binary, "segments", []) or []:
        seg_vaddr = int(getattr(segment, "virtual_address", 0) or 0)
        seg_offset = int(getattr(segment, "file_offset", 0) or 0)
        file_size = int(getattr(segment, "physical_size", 0) or 0)
        mem_size = int(getattr(segment, "virtual_size", 0) or file_size)
        size = file_size if file_size else mem_size
        if seg_vaddr <= vaddr < seg_vaddr + size:
            return seg_offset + (vaddr - seg_vaddr)

    raise PatchPlanningError(f"Virtual address 0x{vaddr:x} is not mapped to a file offset")


def read_bytes_at_va(elf: ElfBinary, vaddr: int, size: int) -> bytes:
    get_content = getattr(elf.binary, "get_content_from_virtual_address", None)
    if callable(get_content):
        try:
            return bytes(get_content(vaddr, size))
        except Exception:
            pass

    offset = va_to_offset(elf, vaddr)
    with elf.path.open("rb") as fh:
        fh.seek(offset)
        return fh.read(size)


def segment_for_va(elf: ElfBinary, vaddr: int) -> Any | None:
    for segment in getattr(elf.binary, "segments", []) or []:
        seg_vaddr = int(getattr(segment, "virtual_address", 0) or 0)
        size = int(getattr(segment, "virtual_size", 0) or getattr(segment, "physical_size", 0) or 0)
        if seg_vaddr <= vaddr < seg_vaddr + size:
            return segment
    return None


def is_executable_segment(segment: Any) -> bool:
    flags = getattr(segment, "flags", "")
    name = enum_name(flags).upper()
    if "X" in name or "EXEC" in name:
        return True
    try:
        return bool(int(flags) & 0x1)
    except Exception:
        return False


def require_mapped_executable(elf: ElfBinary, vaddr: int) -> None:
    segment = segment_for_va(elf, vaddr)
    if segment is None:
        raise PatchPlanningError(f"Address 0x{vaddr:x} is not inside a mapped segment")
    if not is_executable_segment(segment):
        raise PatchPlanningError(f"Address 0x{vaddr:x} is not inside an executable segment")
