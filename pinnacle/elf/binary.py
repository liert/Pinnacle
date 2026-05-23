"""LIEF-backed ELF loading and architecture checks."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pinnacle.deps import require_lief
from pinnacle.errors import UnsupportedElfError


@dataclass(slots=True)
class ElfBinary:
    path: Path
    binary: Any


def parse_elf(path: str | Path) -> ElfBinary:
    lief = require_lief()
    elf_path = Path(path)
    binary = lief.parse(str(elf_path))
    if binary is None:
        raise UnsupportedElfError(f"Unable to parse ELF: {elf_path}")
    return ElfBinary(path=elf_path, binary=binary)


def enum_name(value: Any) -> str:
    return getattr(value, "name", str(value))


def ensure_aarch64(elf: ElfBinary) -> None:
    machine = getattr(getattr(elf.binary, "header", None), "machine_type", None)
    if machine is None:
        raise UnsupportedElfError("ELF header does not expose machine_type")
    name = enum_name(machine).upper()
    if "AARCH64" not in name and "ARM64" not in name:
        raise UnsupportedElfError(f"Unsupported ELF architecture: {name}")


def ensure_little_endian(elf: ElfBinary) -> None:
    header = getattr(elf.binary, "header", None)
    identity = getattr(header, "identity_data", None)
    if identity is None:
        return
    name = enum_name(identity).upper()
    if "LSB" not in name and "LITTLE" not in name:
        raise UnsupportedElfError(f"Unsupported ELF endianness: {name}")


def ensure_supported_elf(elf: ElfBinary) -> None:
    ensure_aarch64(elf)
    ensure_little_endian(elf)


def section_by_name(elf: ElfBinary, name: str) -> Any | None:
    getter = getattr(elf.binary, "get_section", None)
    if callable(getter):
        sec = getter(name)
        if sec is not None:
            return sec
    for section in getattr(elf.binary, "sections", []) or []:
        if getattr(section, "name", None) == name:
            return section
    return None


def executable_sections(elf: ElfBinary) -> list[Any]:
    sections = []
    for section in getattr(elf.binary, "sections", []) or []:
        flags = enum_name(getattr(section, "flags", "")).upper()
        if "EXEC" in flags or _int_flags(section) & 0x4:
            sections.append(section)
    return sections


def _int_flags(section: Any) -> int:
    value = getattr(section, "flags", 0)
    try:
        return int(value)
    except Exception:
        return 0
