"""Shared data models."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

CallableKind = Literal["defined", "imported"]
PatchStrategy = Literal["overwrite", "trampoline", "codecave"]
SaveMode = Literal["minimal", "safe", "full", "raw"]
PreferMode = Literal["auto", "defined", "imported"]
ReturnMode = Literal["jump", "ret", "none"]
PayloadPlacement = Literal["auto", "codecave", "load-cave", "segment"]


@dataclass(slots=True)
class FunctionSymbol:
    name: str
    vaddr: int
    size: int
    bind: str
    section_index: int | str
    source: str
    lief_symbol: Any | None = None


@dataclass(slots=True)
class ImportedFunction:
    name: str
    dynsym_index: int | None
    plt_vaddr: int
    got_reloc_offset: int | None
    reloc_type: str
    source: str
    lief_symbol: Any | None = None
    lief_relocation: Any | None = None


@dataclass(slots=True)
class CallableTarget:
    name: str
    kind: CallableKind
    call_vaddr: int
    symbol: FunctionSymbol | None = None
    import_: ImportedFunction | None = None


@dataclass(slots=True)
class PatchRequest:
    input_path: Path
    output_path: Path | None
    insert_vaddr: int
    target_function: str | None
    user_asm: str | None
    strategy: PatchStrategy
    mode: SaveMode = "full"
    prefer: PreferMode = "auto"
    return_mode: ReturnMode = "jump"
    payload_placement: PayloadPlacement = "auto"
    payload_vaddr: int | None = None
    external_verify: bool = False
    allow_inline_data: bool = False
    dry_run: bool = False


@dataclass(slots=True)
class PatchPlan:
    insert_vaddr: int
    insert_offset: int
    payload_vaddr: int
    payload_offset: int
    overwritten_bytes: bytes
    payload_asm: str
    payload_bytes: bytes
    entry_patch_asm: str
    entry_patch_bytes: bytes
    payload_in_added_segment: bool = False
    context_vaddr: int | None = None
