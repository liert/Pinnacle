"""Callable symbol resolution."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from pinnacle.errors import SymbolResolutionError
from pinnacle.model import CallableTarget, FunctionSymbol, ImportedFunction, PreferMode

from .binary import ElfBinary, enum_name
from .plt import list_imported_functions


def list_function_symbols(elf: ElfBinary) -> list[FunctionSymbol]:
    symbols: list[FunctionSymbol] = []
    seen: set[tuple[str, int]] = set()
    for source, lief_symbols in (
        (".symtab", getattr(elf.binary, "symbols", []) or []),
        (".dynsym", getattr(elf.binary, "dynamic_symbols", []) or []),
    ):
        for symbol in lief_symbols:
            if not _is_function_symbol(symbol):
                continue
            vaddr = int(getattr(symbol, "value", 0) or 0)
            if vaddr <= 0:
                continue
            key = (getattr(symbol, "name", ""), vaddr)
            if key in seen:
                continue
            seen.add(key)
            symbols.append(
                FunctionSymbol(
                    name=getattr(symbol, "name", ""),
                    vaddr=vaddr,
                    size=int(getattr(symbol, "size", 0) or 0),
                    bind=enum_name(getattr(symbol, "binding", "")),
                    section_index=enum_name(getattr(symbol, "shndx", "")),
                    source=source,
                    lief_symbol=symbol,
                )
            )
    return [sym for sym in symbols if sym.name]


def resolve_callable(elf: ElfBinary, name: str, prefer: PreferMode = "auto") -> CallableTarget:
    defined = [sym for sym in list_function_symbols(elf) if sym.name == name]
    imported = [imp for imp in list_imported_functions(elf) if imp.name == name]

    if prefer == "defined":
        if not defined:
            raise SymbolResolutionError(f"No defined function symbol named '{name}'")
        return _target_from_defined(_pick_defined(defined))
    if prefer == "imported":
        if not imported:
            raise SymbolResolutionError(f"No imported function PLT entry named '{name}'")
        return _target_from_import(imported[0])

    if defined:
        return _target_from_defined(_pick_defined(defined))
    if imported:
        return _target_from_import(imported[0])
    raise SymbolResolutionError(f"No callable function named '{name}'")


def all_callables(elf: ElfBinary) -> list[CallableTarget]:
    targets = [_target_from_defined(sym) for sym in list_function_symbols(elf)]
    targets.extend(_target_from_import(imp) for imp in list_imported_functions(elf))
    return targets


def group_callables_by_name(elf: ElfBinary) -> dict[str, list[CallableTarget]]:
    grouped: dict[str, list[CallableTarget]] = defaultdict(list)
    for target in all_callables(elf):
        grouped[target.name].append(target)
    return dict(grouped)


def _target_from_defined(symbol: FunctionSymbol) -> CallableTarget:
    return CallableTarget(name=symbol.name, kind="defined", call_vaddr=symbol.vaddr, symbol=symbol)


def _target_from_import(imported: ImportedFunction) -> CallableTarget:
    return CallableTarget(
        name=imported.name,
        kind="imported",
        call_vaddr=imported.plt_vaddr,
        import_=imported,
    )


def _pick_defined(symbols: list[FunctionSymbol]) -> FunctionSymbol:
    return sorted(symbols, key=lambda sym: (sym.source != ".symtab", -sym.size, sym.vaddr))[0]


def _is_function_symbol(symbol: Any) -> bool:
    sym_type = enum_name(getattr(symbol, "type", "")).upper()
    if "FUNC" in sym_type:
        return True
    return False
