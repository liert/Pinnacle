from __future__ import annotations

from pathlib import Path

import pytest

from pinnacle.elf.binary import ensure_supported_elf, parse_elf
from pinnacle.elf.plt import list_imported_functions
from pinnacle.elf.symbols import resolve_callable
from pinnacle.model import PatchRequest
from pinnacle.patch.injector import plan_patch
from pinnacle.verify.disasm import disasm_aarch64

ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "server"
pytestmark = pytest.mark.skipif(not SERVER.exists(), reason="local server fixture is not published")


def test_server_imports_resolve_to_plt_entries() -> None:
    elf = parse_elf(SERVER)
    ensure_supported_elf(elf)

    imports = list_imported_functions(elf)

    assert imports
    assert any(item.name == "malloc" and item.plt_vaddr > 0 for item in imports)


def test_resolve_imported_callable_from_server() -> None:
    elf = parse_elf(SERVER)

    target = resolve_callable(elf, "malloc", "imported")

    assert target.kind == "imported"
    assert target.call_vaddr == 0x403100


def test_trampoline_dry_run_plan_for_server_import() -> None:
    request = PatchRequest(
        input_path=SERVER,
        output_path=None,
        insert_vaddr=0x402E48,
        target_function="malloc",
        user_asm=None,
        strategy="trampoline",
        mode="minimal",
        prefer="imported",
        dry_run=True,
    )

    plan = plan_patch(request)

    entry = disasm_aarch64(plan.entry_patch_bytes, plan.insert_vaddr)
    payload = disasm_aarch64(plan.payload_bytes, plan.payload_vaddr)
    assert entry[0].mnemonic == "b"
    assert any(insn.mnemonic == "bl" and "0x403100" in insn.op_str for insn in payload)
    assert plan.overwritten_bytes
