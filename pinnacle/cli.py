"""Command line interface."""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

from pinnacle import __version__
from pinnacle.elf.binary import ensure_supported_elf, parse_elf
from pinnacle.elf.plt import list_imported_functions
from pinnacle.elf.symbols import list_function_symbols
from pinnacle.errors import PinnacleError
from pinnacle.model import PatchRequest
from pinnacle.patch.injector import apply_patch_plan, plan_patch


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except PinnacleError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pinnacle", description="AArch64 ELF call injection toolkit")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    list_symbols = sub.add_parser("list-symbols", help="List defined function symbols")
    list_symbols.add_argument("input", type=Path)
    list_symbols.set_defaults(func=cmd_list_symbols)

    list_imports = sub.add_parser("list-imports", help="List imported functions resolved to PLT entries")
    list_imports.add_argument("input", type=Path)
    list_imports.set_defaults(func=cmd_list_imports)

    inject = sub.add_parser("inject", help="Plan or apply an AArch64 patch")
    inject.add_argument("--input", required=True, type=Path)
    inject.add_argument("--output", type=Path)
    inject.add_argument("--addr", required=True, type=parse_int)
    inject.add_argument("--call")
    inject.add_argument("--prefer", choices=["auto", "defined", "imported"], default="auto")
    inject.add_argument("--asm", dest="asm_path", type=Path)
    inject.add_argument("--strategy", choices=["overwrite", "trampoline", "codecave"], default="trampoline")
    inject.add_argument("--mode", choices=["minimal", "safe", "raw"], default="safe")
    inject.add_argument("--payload-addr", type=parse_int)
    inject.add_argument(
        "--payload-placement",
        choices=["auto", "codecave", "segment"],
        default="auto",
        help="Where to place trampoline payloads: executable code cave, new executable segment, or auto",
    )
    inject.add_argument(
        "--return-mode",
        choices=["jump", "ret", "none"],
        default="jump",
        help="How payload exits: jump back to original flow, ret to caller, or leave exit code to --asm",
    )
    inject.add_argument("--dry-run", action="store_true")
    inject.add_argument("--external-verify", action="store_true")
    inject.add_argument(
        "--allow-inline-data",
        action="store_true",
        help="Allow raw payloads with embedded data such as .asciz strings",
    )
    inject.set_defaults(func=cmd_inject)

    return parser


def cmd_list_symbols(args: argparse.Namespace) -> int:
    elf = parse_elf(args.input)
    ensure_supported_elf(elf)
    for sym in list_function_symbols(elf):
        print(f"0x{sym.vaddr:016x} {sym.size:8d} {sym.source:8s} {sym.name}")
    return 0


def cmd_list_imports(args: argparse.Namespace) -> int:
    elf = parse_elf(args.input)
    ensure_supported_elf(elf)
    for imp in list_imported_functions(elf):
        reloc = f"0x{imp.got_reloc_offset:x}" if imp.got_reloc_offset is not None else "-"
        print(f"0x{imp.plt_vaddr:016x} {reloc:>18s} {imp.reloc_type:24s} {imp.name}@plt")
    return 0


def cmd_inject(args: argparse.Namespace) -> int:
    if args.call is None and args.asm_path is None:
        raise PinnacleError("inject requires --call, --asm, or both")
    if not args.dry_run and args.output is None:
        raise PinnacleError("inject requires --output unless --dry-run is used")

    try:
        user_asm = args.asm_path.read_text(encoding="utf-8") if args.asm_path else None
    except OSError as exc:
        raise PinnacleError(f"Unable to read --asm file '{args.asm_path}': {exc}") from exc
    request = PatchRequest(
        input_path=args.input,
        output_path=args.output,
        insert_vaddr=args.addr,
        target_function=args.call,
        user_asm=user_asm,
        strategy=args.strategy,
        mode=args.mode,
        prefer=args.prefer,
        return_mode=args.return_mode,
        payload_placement=args.payload_placement,
        payload_vaddr=args.payload_addr,
        external_verify=args.external_verify,
        allow_inline_data=args.allow_inline_data,
        dry_run=args.dry_run,
    )
    plan = plan_patch(request)
    print_plan(plan)
    if args.external_verify:
        warn_missing_external_tools()
    apply_patch_plan(request, plan)
    return 0


def print_plan(plan) -> None:
    print(f"insert_vaddr: 0x{plan.insert_vaddr:x}")
    print(f"insert_offset: 0x{plan.insert_offset:x}")
    print(f"payload_vaddr: 0x{plan.payload_vaddr:x}")
    print(f"payload_offset: 0x{plan.payload_offset:x}")
    print(f"entry_patch_len: {len(plan.entry_patch_bytes)}")
    print(f"payload_len: {len(plan.payload_bytes)}")
    if plan.overwritten_bytes:
        print(f"overwritten_len: {len(plan.overwritten_bytes)}")
    print("entry_patch_asm:")
    print(_indent(plan.entry_patch_asm))
    print("payload_asm:")
    print(_indent(plan.payload_asm))


def warn_missing_external_tools() -> None:
    for tool in ("objdump", "readelf", "qemu-aarch64"):
        if shutil.which(tool) is None:
            print(f"warning: optional external tool not found: {tool}", file=sys.stderr)


def parse_int(text: str) -> int:
    return int(text, 0)


def _indent(text: str) -> str:
    return "\n".join(f"  {line}" if line else "" for line in text.splitlines())


if __name__ == "__main__":
    raise SystemExit(main())
