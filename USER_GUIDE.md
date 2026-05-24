# Pinnacle 用户指南

语言：中文 | [English](USER_GUIDE.en.md)

这份文档面向从终端使用 Pinnacle 的用户。

## Pinnacle 做什么

Pinnacle 可以在 AArch64 Linux ELF 的指定虚拟地址处插入补丁。它可以：

- 通过 PLT 入口查找 `malloc`、`fopen`、`unlink` 等导入函数。
- 生成调用这些函数的 AArch64 汇编。
- 汇编自定义 hook 代码。
- 在可执行 Section 的 code cave 中放置 payload；如果没有足够空间，可以新增可执行 `PT_LOAD` 段。

## 推荐流程

1. 查看导入函数：

```powershell
.\.venv\Scripts\python.exe -m pinnacle.cli list-imports target.elf
```

2. 查看本地函数符号：

```powershell
.\.venv\Scripts\python.exe -m pinnacle.cli list-symbols target.elf
```

3. 先执行 dry-run：

```powershell
.\.venv\Scripts\python.exe -m pinnacle.cli inject `
  --input target.elf `
  --addr 0x4294A8 `
  --asm examples\call_import_malloc.asm `
  --strategy trampoline `
  --mode raw `
  --return-mode none `
  --dry-run
```

4. 确认计划无误后写出补丁文件：

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

## 重要参数

- `--input`：输入 ELF。
- `--output`：输出 patched ELF。
- `--addr`：需要 patch 的虚拟地址。
- `--call`：要调用的函数名。
- `--prefer imported`：优先使用导入函数 PLT。
- `--asm`：自定义汇编模板文件。
- `--strategy trampoline`：从目标地址跳到 payload。
- `--payload-placement auto`：默认策略，先找可执行 Section 的 code cave，找不到则新增可执行 `PT_LOAD` 段。
- `--payload-placement codecave`：只允许使用可执行 Section 中的 code cave。
- `--payload-placement load-cave`：只使用已有可执行 `PT_LOAD` 中的空洞，适合后续还要 UPX 打包的场景。
- `--payload-placement segment`：强制新增可执行 `PT_LOAD` 段放置 payload。
- `--mode`：兼容旧用法，不推荐新 hook 依赖它组合出口行为；默认 `full` 会在入口保存 `x0-x30` 和 `NZCV`。工具会自动扩展 ELF 的可写 NOBITS 区域，通常是 `.bss`，把完整上下文放到新扩出的运行时缓冲区；入口只临时使用 16 字节栈空间保存寻址 scratch 寄存器。
- `--return-mode jump`：payload 末尾跳回原流程。
- `--return-mode ret`：payload 末尾追加 `ret`。
- `--return-mode none`：payload 末尾不追加任何内容。
- `--allow-inline-data`：允许 raw payload 中包含 `.asciz` 等内联数据。
- `--dry-run`：只打印 patch 计划，不写文件。

## 让 IDA 更容易识别 payload 为函数

## 出口标记

推荐直接在 asm 中写出口标记：

```asm
ret
ret_restore
ret_jump 0x426cc8
ret_restore_jump 0x426cc8
```

- `ret`：不恢复现场，直接返回。
- `ret_restore`：恢复所有寄存器和 `NZCV` 后返回。
- `ret_jump 0xADDR`：不恢复现场，直接跳到目标地址。
- `ret_restore_jump 0xADDR`：恢复所有寄存器和 `NZCV` 后跳到目标地址。

如果没有任何 `ret...` 标记，工具默认从同一块上下文缓冲区恢复所有寄存器和 `NZCV`，然后跳回原流程。

## 示例汇编

仓库提供了一个可公开的通用示例：

```text
examples/call_import_malloc.asm
```

它调用导入函数 `malloc(16)`，并将返回值保留在 `x0`。项目特定的 hook payload 建议放在本地忽略目录，例如 `hooks/`。

## 常见问题

如果缺少依赖：

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

如果不希望自动新增可执行段，也可以手动指定一个可执行 payload 地址：

```powershell
--payload-addr 0x430c48
```

如果补丁后还要使用 UPX，优先使用：

```powershell
--payload-placement load-cave
```

如果 `trampoline` 拒绝 patch，通常是被覆盖指令中包含 PC-relative 指令。可以换一个地址，或选择更适合目标位置的注入策略。
