"""Patch planning orchestration."""

from __future__ import annotations

from pinnacle.asm.aarch64_call import (
    branch_abs,
    call_abs,
    restore_all_context_static,
    save_all_context_static,
    wrap_payload,
)
from pinnacle.asm.assembler import assemble_aarch64
from pinnacle.asm.templates import expand_template, merge_user_and_generated
from pinnacle.elf.address import is_writable_segment, require_mapped_executable, segment_for_va, va_to_offset
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
    expanded = expand_template(
        merged,
        resolver,
        insert_vaddr=request.insert_vaddr,
        prefer=request.prefer,
    )
    context_vaddr = _context_location(elf) if request.mode == "full" else None
    if context_vaddr is not None:
        _reserve_context_buffer(elf, context_vaddr)
    if request.strategy == "overwrite":
        payload_vaddr = request.insert_vaddr
        payload_added_segment = False
        payload_asm = _build_payload_asm(expanded, request, None, payload_vaddr, context_vaddr)
        payload_bytes = assemble_aarch64(payload_asm, payload_vaddr)
        _verify_payload(payload_bytes, payload_vaddr, request)
        payload_offset = va_to_offset(elf, payload_vaddr)
        insert_offset = va_to_offset(elf, request.insert_vaddr)
        entry_patch_asm = payload_asm
        entry_patch_bytes = payload_bytes
        overwritten = b""
    else:
        estimated_payload = _build_payload_asm(expanded, request, request.insert_vaddr + 4, request.insert_vaddr, context_vaddr)
        payload_vaddr, payload_added_segment = _payload_location(elf, request, estimated_payload)
        entry_patch_asm, entry_patch_bytes = entry_branch_bytes(request.insert_vaddr, payload_vaddr)
        ensure_decodable(entry_patch_bytes, request.insert_vaddr)
        overwritten = overwritten_for_entry_branch(elf, request.insert_vaddr, len(entry_patch_bytes))
        return_vaddr = request.insert_vaddr + len(overwritten)
        payload_asm = _build_payload_asm(expanded, request, return_vaddr, payload_vaddr, context_vaddr)
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
        context_vaddr=context_vaddr,
    )


def apply_patch_plan(request: PatchRequest, plan: PatchPlan) -> None:
    if request.dry_run:
        return
    if request.output_path is None:
        raise PatchPlanningError("output_path is required when dry_run is false")

    # Re-parse the original for mutation so dry-run planning remains side-effect free.
    elf = parse_elf(request.input_path)
    if plan.context_vaddr is not None:
        context_vaddr = _context_location(elf)
        if context_vaddr != plan.context_vaddr:
            raise PatchPlanningError(
                f"Context buffer VA changed from 0x{plan.context_vaddr:x} to 0x{context_vaddr:x}; rerun planning"
            )
        _reserve_context_buffer(elf, plan.context_vaddr)
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


def _context_location(elf) -> int:
    size = 256
    candidates: list[tuple[int, int, str, int]] = []
    for section in getattr(elf.binary, "sections", []) or []:
        name = str(getattr(section, "name", "") or "")
        sec_size = int(getattr(section, "size", 0) or 0)
        vaddr = int(getattr(section, "virtual_address", 0) or 0)
        if vaddr == 0 or sec_size < size or not _is_writable_section(section):
            continue
        segment = segment_for_va(elf, vaddr)
        if segment is None or not is_writable_segment(segment):
            continue
        if not _is_nobits_section(section) and name != ".bss":
            continue
        context_vaddr = _align16(vaddr + sec_size)
        context_end = context_vaddr + size
        next_section_vaddr = _next_alloc_section_vaddr(elf, vaddr + sec_size)
        if next_section_vaddr is not None and context_end > next_section_vaddr:
            continue
        priority = 0 if name == ".bss" else 1
        candidates.append((priority, sec_size, name, context_vaddr))

    if not candidates:
        raise PatchPlanningError(
            "No writable NOBITS context buffer was found for full register preservation"
        )

    candidates.sort(key=lambda item: (item[0], -item[1], item[2]))
    return candidates[0][3]


def _reserve_context_buffer(elf, context_vaddr: int) -> None:
    context_end = context_vaddr + 256
    for section in getattr(elf.binary, "sections", []) or []:
        vaddr = int(getattr(section, "virtual_address", 0) or 0)
        sec_size = int(getattr(section, "size", 0) or 0)
        if vaddr == 0 or not _is_writable_section(section) or not _is_nobits_section(section):
            continue
        if _align16(vaddr + sec_size) != context_vaddr:
            continue
        section.size = context_end - vaddr
        segment = segment_for_va(elf, vaddr)
        if segment is None or not is_writable_segment(segment):
            raise PatchPlanningError("Context section is not inside a writable segment")
        seg_end = int(getattr(segment, "virtual_address", 0) or 0) + int(getattr(segment, "virtual_size", 0) or 0)
        if context_end > seg_end:
            segment.virtual_size = int(getattr(segment, "virtual_size", 0) or 0) + (context_end - seg_end)
        return
    raise PatchPlanningError(f"Unable to reserve context buffer at 0x{context_vaddr:x}")


def _next_alloc_section_vaddr(elf, after_vaddr: int) -> int | None:
    values: list[int] = []
    for section in getattr(elf.binary, "sections", []) or []:
        vaddr = int(getattr(section, "virtual_address", 0) or 0)
        if vaddr > after_vaddr:
            values.append(vaddr)
    return min(values) if values else None


def _is_writable_section(section) -> bool:
    flags = getattr(section, "flags", 0)
    try:
        return bool(int(flags) & 0x1)
    except Exception:
        return "WRITE" in str(flags).upper() or "W" in str(flags).upper()


def _is_nobits_section(section) -> bool:
    sec_type = getattr(section, "type", "")
    return "NOBITS" in str(sec_type).upper()


def _align16(value: int) -> int:
    return (value + 15) & ~15


def _build_payload_asm(
    expanded_asm: str,
    request: PatchRequest,
    return_vaddr: int | None,
    payload_vaddr: int,
    context_vaddr: int | None,
) -> str:
    if request.mode == "full":
        if context_vaddr is None:
            raise PatchPlanningError("full mode requires a writable context buffer")
        return _apply_full_context_markers(expanded_asm, return_vaddr, context_vaddr)
    payload_body = wrap_payload(expanded_asm, request.mode)
    return _finish_payload(payload_body, request, return_vaddr, payload_vaddr)


def _apply_full_context_markers(expanded_asm: str, return_vaddr: int | None, context_vaddr: int) -> str:
    marker_seen = False
    lines: list[str] = []
    for raw_line in expanded_asm.splitlines():
        stripped = raw_line.strip()
        parts = stripped.split()
        if not parts or not parts[0].startswith("ret"):
            lines.append(raw_line)
            continue

        marker = parts[0]
        if marker == "ret":
            marker_seen = True
            lines.append("ret")
        elif marker == "ret_restore":
            marker_seen = True
            lines.extend(restore_all_context_static(context_vaddr).splitlines())
            lines.append("ret")
        elif marker == "ret_jump" and len(parts) == 2:
            marker_seen = True
            lines.append(f"b 0x{int(parts[1], 0):x}")
        elif marker == "ret_restore_jump" and len(parts) == 2:
            marker_seen = True
            lines.extend(restore_all_context_static(context_vaddr).splitlines())
            lines.append(f"b 0x{int(parts[1], 0):x}")
        else:
            lines.append(raw_line)

    if not marker_seen:
        lines.extend(restore_all_context_static(context_vaddr).splitlines())
        if return_vaddr is None:
            lines.append("ret")
        else:
            lines.append(f"b 0x{return_vaddr:x}")
    return "\n".join([save_all_context_static(context_vaddr), *lines])


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
