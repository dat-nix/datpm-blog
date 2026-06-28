---
title: "banned_bytes: ROP chain khi byteset bị filter"
date: 2026-06-28
category: "CTF · Binary Exploitation"
tags: ["pwn", "rop", "x86-64", "tbctf"]
excerpt: "Bài này filter hết các byte thông dụng trong gadget. Giải pháp: XOR-encode payload, tự viết decoder stub vào BSS, rồi jump sang đó. Mất 6 tiếng mới ra được chain hoàn chỉnh."
---

## Overview

Challenge từ TBCTF 2025. Binary 64-bit, có stack overflow nhưng filter một số byte nhất định — tức là không phải gadget nào cũng dùng được.

```
$ checksec banned_bytes
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE
```

NX enabled → shellcode không chạy được. Không có canary → overflow thẳng. No PIE → địa chỉ cố định.

## Phân tích filter

```python
banned = [0x0a, 0x00, 0x0b, ...]
```

Vấn đề: nhiều gadget phổ biến như `pop rdi; ret` có địa chỉ chứa byte bị ban.

## Giải pháp: XOR stub

Thay vì dùng gadget trực tiếp, mình:

1. XOR-encode toàn bộ payload với key không chứa byte bị ban
2. Dùng ROP chain ngắn để ghi stub decoder vào BSS
3. Jump sang stub, stub tự decode rồi execute

```python
from pwn import *

elf = ELF('./banned_bytes')
rop = ROP(elf)

BSS = elf.bss(0x100)
KEY = 0x41  # byte 'A', không bị ban

# Stage 1: ghi XOR decoder vào BSS
# ...
```

## Bài học

Khi ROP bị constrain, không cố tìm gadget "perfect" — thay vào đó tự build primitive nhỏ hơn và chain lại. Đây là mindset quan trọng hơn biết nhiều gadget.

Flag: `NCT{r0p_wh3n_bytes_are_banned}`
