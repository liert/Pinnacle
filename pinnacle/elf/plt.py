"""Imported-function and PLT resolution."""

from __future__ import annotations

from typing import Any, Iterable

from pinnacle.model import ImportedFunction

from .binary import ElfBinary, enum_name, section_by_name


def list_imported_functions(elf: ElfBinary) -> list[ImportedFunction]:
    relocations = _plt_relocations(elf)
    plt_entries = _infer_plt_entries(elf, len(relocations))
    imports: list[ImportedFunction] = []

    for index, relocation in enumerate(relocations):
        symbol = getattr(relocation, "symbol", None)
        name = getattr(symbol, "name", None)
        if not name:
            continue
        plt_vaddr = _relocation_plt_address(relocation)
        if plt_vaddr is None:
            plt_vaddr = plt_entries[index] if index < len(plt_entries) else None
        if plt_vaddr is None:
            continue
        imports.append(
            ImportedFunction(
                name=name,
                dynsym_index=_symbol_index(symbol),
                plt_vaddr=int(plt_vaddr),
                got_reloc_offset=_relocation_address(relocation),
                reloc_type=enum_name(getattr(relocation, "type", "")),
                source=".rela.plt",
                lief_symbol=symbol,
                lief_relocation=relocation,
            )
        )
    return imports


def _plt_relocations(elf: ElfBinary) -> list[Any]:
    candidates = getattr(elf.binary, "pltgot_relocations", None)
    if candidates is None:
        candidates = []
    relocs = [rel for rel in candidates if _is_jump_slot(rel)]
    if relocs:
        return relocs
    return [rel for rel in getattr(elf.binary, "relocations", []) or [] if _is_jump_slot(rel)]


def _is_jump_slot(relocation: Any) -> bool:
    text = enum_name(getattr(relocation, "type", "")).upper()
    return "JUMP_SLOT" in text


def _relocation_address(relocation: Any) -> int | None:
    for attr in ("address", "virtual_address"):
        value = getattr(relocation, attr, None)
        if value is not None:
            return int(value)
    return None


def _relocation_plt_address(relocation: Any) -> int | None:
    for attr in ("plt_address", "plt_addr", "plt_value"):
        value = getattr(relocation, attr, None)
        if value is not None:
            return int(value)
    return None


def _symbol_index(symbol: Any) -> int | None:
    for attr in ("idx", "index", "symbol_index"):
        value = getattr(symbol, attr, None)
        if value is not None:
            return int(value)
    return None


def _infer_plt_entries(elf: ElfBinary, relocation_count: int) -> list[int]:
    if relocation_count <= 0:
        return []
    section = section_by_name(elf, ".plt") or section_by_name(elf, ".plt.sec")
    if section is None:
        return []
    start = int(getattr(section, "virtual_address", 0) or 0)
    size = int(getattr(section, "size", 0) or 0)
    entry_size = 16
    plt0_size = size - relocation_count * entry_size
    if start <= 0 or plt0_size < 0 or plt0_size % entry_size != 0:
        return []
    return [start + plt0_size + i * entry_size for i in range(relocation_count)]
