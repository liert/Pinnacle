# Pinnacle

语言：中文 | [English](README.en.md)

Pinnacle 是一个 Python 工具，用于规划和应用 AArch64 ELF 调用注入补丁。它可以从 ELF 符号和导入函数 PLT 入口解析已有函数，生成 AArch64 payload，并通过 overwrite 或 trampoline 策略 patch 指定地址。

工具本身支持在 Windows 和 Linux 上运行。第一版目标文件格式为 AArch64 Linux ELF。

## 功能

- 基于 LIEF 解析和写回 ELF。
- 解析导入函数对应的 PLT 入口。
- 使用 Keystone 汇编 AArch64 代码。
- 使用 Capstone 验证补丁反汇编。
- 支持带伪指令的自定义汇编模板。
- 支持 trampoline 注入，优先寻找可执行 Section 中的 code cave；找不到时可新增 `R|X PT_LOAD` 段放置 payload。

## 安装

Windows PowerShell：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Linux/macOS shell：

```bash
python3 -m venv .venv
./.venv/bin/python -m pip install -r requirements.txt
```

## 基本用法

查看目标 ELF 的导入函数 PLT：

```powershell
.\.venv\Scripts\python.exe -m pinnacle.cli list-imports target.elf
```

查看本地函数符号：

```powershell
.\.venv\Scripts\python.exe -m pinnacle.cli list-symbols target.elf
```

只生成 patch 计划，不写文件：

```powershell
.\.venv\Scripts\python.exe -m pinnacle.cli inject `
  --input target.elf `
  --addr 0x4294A8 `
  --call malloc `
  --prefer imported `
  --strategy trampoline `
  --mode minimal `
  --dry-run
```

写出 patched ELF：

```powershell
.\.venv\Scripts\python.exe -m pinnacle.cli inject `
  --input target.elf `
  --output target.patched `
  --addr 0x4294A8 `
  --call malloc `
  --prefer imported `
  --strategy trampoline `
  --mode minimal
```

## 自定义汇编

使用 `--asm` 指定汇编模板：

```powershell
.\.venv\Scripts\python.exe -m pinnacle.cli inject `
  --input target.elf `
  --output target.patched `
  --addr 0x4294A8 `
  --asm examples\call_import_malloc.asm `
  --strategy trampoline `
  --mode raw `
  --return-mode none
```

当前支持的伪指令：

```asm
call_symbol malloc
call_import malloc
load_symbol_addr x16, malloc
branch_abs 0x402e4c
```

推荐在 asm 中使用 `ret...` 标记描述出口行为，而不是依赖 `--mode` 组合。`--mode` 仅保留为兼容旧用法。

默认 `--mode full` 会在 payload 入口保存 `x0-x30` 和 `NZCV`。出口由 asm 中的特殊标记控制：

```asm
ret                         // 不恢复现场，直接返回
ret_restore                 // 恢复所有寄存器和 NZCV 后返回
ret_jump 0x426cc8           // 不恢复现场，直接跳转
ret_restore_jump 0x426cc8   // 恢复所有寄存器和 NZCV 后跳转
```

如果没有任何 `ret...` 标记，默认会恢复所有寄存器和 `NZCV`，然后跳回原流程。

如果汇编中包含 `.asciz` 这类内联数据，需要加上 `--allow-inline-data`，否则 Capstone 会尝试把数据区也当成指令反汇编。

payload 默认放置策略为 `--payload-placement auto`：先找可执行 Section 中的 code cave，避免把代码放进 `.rodata`；如果没有足够空间，则新增一个可执行 `PT_LOAD` 段。也可以显式使用 `--payload-placement segment`。

如果 patched ELF 后续还需要用 UPX 打包，建议使用 `--payload-placement load-cave`。该模式只使用已有可执行 `PT_LOAD` 中的空洞，不新增 Program Header，能避免 UPX 对新增段布局报 `bad e_phoff`。

## 注意事项

- 建议先使用 `--dry-run` 查看生成的 `entry_patch_asm` 和 `payload_asm`。
- `objdump`、`readelf`、`qemu-aarch64` 等外部工具是可选增强工具，不是运行时依赖。
- 本地测试程序、私有 hook 汇编和开发规划文档不会上传到公开仓库。

更多人类友好的说明见 [USER_GUIDE.md](USER_GUIDE.md)。AI/自动化代理可参考 [AI_USAGE.md](AI_USAGE.md)。
