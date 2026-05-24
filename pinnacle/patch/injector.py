"""Patch planning orchestration."""

from __future__ import annotations

from pinnacle.asm.aarch64_call import branch_abs, call_abs, wrap_payload
from pinnacle.asm.assembler import assemble_aarch64
from pinnacle.asm.templates import expand_template, merge_user_and_generated
from pinnacle.elf.address import require_mapped_executable, va_to_offset
from pinnacle.elf.binary import ensure_supported_elf, parse_elf
from pinnacle.elf.symbols import resolve_callable
from pinnacle.errors import PatchPlanningError
from pinnacle.model import CallableTarget, PatchPlan, PatchRequest
from pinnacle.patch.codecave import find_code_cave, find_executable_load_cave
from pinnacle.patch.trampoline import entry_branch_bytes, overwritten_for_entry_branch
from pinnacle.patch.writer import add_executable_segment, patch_bytes, write_binary
from pinnacle.verify.checks import require_aligned_aarch64
from pinnacle.verify.disasm import disasm_aarch64, ensure_decodable


def plan_patch(request: PatchRequest) -> PatchPlan:
    elf = parse_elf(request.input_path)
    ensure_supported_elf(elf)
    require_aligned_aarch64(request.insert_vaddr)
    require_mapped_executable(elf, request.insert_vaddr)

    target = _resolve_target_if_requested(elf, request)
    generated_call = call_abs(target.call_vaddr, request.insert_vaddr) if target else ""

    def resolver(name: str, prefer: str = request.prefer) -> CallableTarget:
        return resolve_callable(elf, name, prefer)  # type: ignore[arg-type]

    merged = merge_user_and_generated(request.user_asm, generated_call)
    if not merged.strip():
        raise PatchPlanningError("--call and --asm cannot both be empty")
    _reject_unsupported_full_wrapper(request, merged)
    expanded = expand_template(
        merged,
        resolver,
        insert_vaddr=request.insert_vaddr,
        prefer=request.prefer,
    )
    if request.strategy == "overwrite":
        payload_vaddr = request.insert_vaddr
        payload_added_segment = False
        payload_body = wrap_payload(expanded, request.mode)
        payload_asm = _finish_payload(payload_body, request, None, payload_vaddr)
        payload_bytes = assemble_aarch64(payload_asm, payload_vaddr)
        _verify_payload(payload_bytes, payload_vaddr, request)
        payload_offset = va_to_offset(elf, payload_vaddr)
        insert_offset = va_to_offset(elf, request.insert_vaddr)
        entry_patch_asm = payload_asm
        entry_patch_bytes = payload_bytes
        overwritten = b""
    else:
        payload_body = wrap_payload(expanded, request.mode)
        payload_vaddr, payload_added_segment = _payload_location(elf, request, payload_body)
        entry_patch_asm, entry_patch_bytes = entry_branch_bytes(request.insert_vaddr, payload_vaddr)
        ensure_decodable(entry_patch_bytes, request.insert_vaddr)
        overwritten = overwritten_for_entry_branch(elf, request.insert_vaddr, len(entry_patch_bytes))
        return_vaddr = request.insert_vaddr + len(overwritten)
        payload_asm = _finish_payload(payload_body, request, return_vaddr, payload_vaddr)
        payload_bytes = assemble_aarch64(payload_asm, payload_vaddr)
        _verify_payload(payload_bytes, payload_vaddr, request)
        payload_offset = va_to_offset(elf, payload_vaddr)
        insert_offset = va_to_offset(elf, request.insert_vaddr)

    return PatchPlan(
        insert_vaddr=request.insert_vaddr,
        insert_offset=insert_offset,
        payload_vaddr=payload_vaddr,
        payload_offset=payload_offset,
        overwritten_bytes=overwritten,
        payload_asm=payload_asm,
        payload_bytes=payload_bytes,
        entry_patch_asm=entry_patch_asm,
        entry_patch_bytes=entry_patch_bytes,
        payload_in_added_segment=payload_added_segment,
    )


def apply_patch_plan(request: PatchRequest, plan: PatchPlan) -> None:
    if request.dry_run:
        return
    if request.output_path is None:
        raise PatchPlanningError("output_path is required when dry_run is false")

    # Re-parse the original for mutation so dry-run planning remains side-effect free.
    elf = parse_elf(request.input_path)
    if request.strategy == "overwrite":
        patch_bytes(elf, request.insert_vaddr, plan.entry_patch_bytes)
    else:
        if plan.payload_in_added_segment:
            payload_vaddr, _ = add_executable_segment(elf, plan.payload_bytes)
            if payload_vaddr != plan.payload_vaddr:
                raise PatchPlanningError(
                    f"Added segment VA changed from 0x{plan.payload_vaddr:x} to 0x{payload_vaddr:x}; rerun planning"
                )
        else:
            patch_bytes(elf, plan.payload_vaddr, plan.payload_bytes)
        patch_bytes(elf, request.insert_vaddr, plan.entry_patch_bytes)
    write_binary(elf, request.output_path)


def _resolve_target_if_requested(elf, request: PatchRequest) -> CallableTarget | None:
    if request.target_function:
        return resolve_callable(elf, request.target_function, request.prefer)
    return None


def _reject_unsupported_full_wrapper(request: PatchRequest, asm: str) -> None:
    if request.mode != "full":
        return
    lowered = asm.lower()
    if request.allow_inline_data or ".asciz" in lowered or ".ascii" in lowered or ".byte" in lowered:
        raise PatchPlanningError(
            "--mode full cannot safely wrap payloads with inline data; use --mode raw and save/restore in the hook"
        )
    if "branch_abs" in lowered or re_search_branch_exit(lowered):
        raise PatchPlanningError(
            "--mode full cannot safely wrap payloads with direct branch exits; use --mode raw and restore before each exit"
        )


def re_search_branch_exit(text: str) -> bool:
    return any(line.strip().startswith(("b 0x", "br ", "ret")) for line in text.splitlines())


def _payload_location(elf, request: PatchRequest, payload_asm: str) -> tuple[int, bool]:
    if request.strategy == "overwrite":
        return request.insert_vaddr, False
    if request.payload_vaddr is not None:
        require_aligned_aarch64(request.payload_vaddr)
        require_mapped_executable(elf, request.payload_vaddr)
        return request.payload_vaddr, False
    estimated = max(assemble_aarch64(payload_asm, request.insert_vaddr).__len__() + 32, 64)
    if request.payload_placement in ("auto", "codecave"):
        cave = find_code_cave(elf, estimated)
        if cave is not None:
            return cave[0], False
        if request.payload_placement == "codecave":
            raise PatchPlanningError("No executable section code cave found; pass --payload-placement segment or --payload-addr")
    if request.payload_placement == "load-cave":
        cave = find_executable_load_cave(elf, estimated)
        if cave is None:
            raise PatchPlanningError("No executable LOAD code cave found; pass --payload-placement segment or --payload-addr")
        return cave[0], False
    dummy = b"\x1f\x20\x03\xd5" * ((estimated + 3) // 4)
    payload_vaddr, _ = add_executable_segment(elf, dummy)
    return payload_vaddr, True


def _finish_payload(
    payload_body: str,
    request: PatchRequest,
    return_vaddr: int | None,
    payload_vaddr: int,
) -> str:
    if request.return_mode == "none":
        return payload_body
    if request.return_mode == "ret":
        return f"{payload_body}\nret"
    if return_vaddr is None:
        return payload_body
    return f"{payload_body}\n{branch_abs(return_vaddr, payload_vaddr)}"


def _verify_payload(payload_bytes: bytes, payload_vaddr: int, request: PatchRequest) -> None:
    if not request.allow_inline_data:
        ensure_decodable(payload_bytes, payload_vaddr)
        return
    if not disasm_aarch64(payload_bytes, payload_vaddr):
        raise PatchPlanningError("Payload contains no decodable AArch64 instruction")
