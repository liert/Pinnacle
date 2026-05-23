"""User assembly template expansion."""

from __future__ import annotations

import re
from collections.abc import Callable

from pinnacle.elf.symbols import resolve_callable
from pinnacle.model import CallableTarget, PreferMode

from .aarch64_call import branch_abs, call_abs, load_abs

ResolveFn = Callable[[str, PreferMode], CallableTarget]


def expand_template(
    template: str,
    resolve: ResolveFn,
    *,
    insert_vaddr: int,
    return_vaddr: int | None = None,
    prefer: PreferMode = "auto",
) -> str:
    lines: list[str] = []
    callsite = insert_vaddr
    for raw_line in template.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("#"):
            lines.append(raw_line)
            continue
        expanded = _expand_line(stripped, resolve, callsite, prefer)
        if expanded is None:
            expanded = raw_line
        lines.append(expanded)
        callsite += _estimated_instruction_count(expanded) * 4

    text = "\n".join(lines)
    values = {
        "insert_addr": f"0x{insert_vaddr:x}",
        "return_addr": f"0x{return_vaddr:x}" if return_vaddr is not None else "0x0",
    }
    return text.format_map(_SafeFormat(values))


def merge_user_and_generated(user_asm: str | None, generated_call: str) -> str:
    if user_asm is None or not user_asm.strip():
        return generated_call
    if "{generated_call}" in user_asm:
        return user_asm.replace("{generated_call}", generated_call)
    return f"{user_asm.rstrip()}\n{generated_call}"


def _expand_line(
    line: str,
    resolve: ResolveFn,
    callsite: int,
    prefer: PreferMode,
) -> str | None:
    call_match = re.fullmatch(r"call_symbol\s+([A-Za-z_.$][\w.$@]*)", line)
    if call_match:
        target = resolve(call_match.group(1), prefer)
        return call_abs(target.call_vaddr, callsite)

    import_match = re.fullmatch(r"call_import\s+([A-Za-z_.$][\w.$@]*)", line)
    if import_match:
        target = resolve(import_match.group(1), "imported")
        return call_abs(target.call_vaddr, callsite)

    load_match = re.fullmatch(r"load_symbol_addr\s+([wx]?\d+|x1[6-7]),\s*([A-Za-z_.$][\w.$@]*)", line)
    if load_match:
        target = resolve(load_match.group(2), prefer)
        return load_abs(load_match.group(1), target.call_vaddr)

    branch_match = re.fullmatch(r"branch_abs\s+(0x[0-9a-fA-F]+|\d+)", line)
    if branch_match:
        return branch_abs(int(branch_match.group(1), 0), callsite)

    return None


def _estimated_instruction_count(asm: str) -> int:
    return sum(1 for line in asm.splitlines() if line.strip() and not line.strip().startswith(("//", "#")))


class _SafeFormat(dict):
    def __missing__(self, key: str) -> str:
        return "{" + key + "}"
