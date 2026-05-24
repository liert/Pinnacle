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
- `--mode minimal`：由工具包一层较小的函数头和函数尾。
- `--mode raw`：工具不包装 payload，汇编文件自己负责函数头和函数尾。
- `--return-mode jump`：payload 末尾跳回原流程。
- `--return-mode ret`：payload 末尾追加 `ret`。
- `--return-mode none`：payload 末尾不追加任何内容。
- `--allow-inline-data`：允许 raw payload 中包含 `.asciz` 等内联数据。
- `--dry-run`：只打印 patch 计划，不写文件。

## 让 IDA 更容易识别 payload 为函数

如果希望 IDA 更容易识别 payload，可以让汇编文件自己写成标准函数形态：

```asm
stp x29, x30, [sp, #-16]!
mov x29, sp
...
ldp x29, x30, [sp], #16
ret
```

注入时使用：

```powershell
--mode raw --return-mode none
```

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
