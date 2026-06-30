---
title: "banned_bytes: ROP chain khi byteset bị filter"
date: 2026-06-28
category: "CTF · Binary Exploitation"
tags: ["pwn", "rop", "x86-64", "tbctf"]
excerpt: "Challenge filter một số byte trong địa chỉ gadget, nên chain trực tiếp không ổn định. Ghi chú này đi qua hướng XOR-encode payload, đặt decoder stub vào BSS, rồi chuyển luồng thực thi sang đó."
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

Khi ROP bị constrain, thay vì cố tìm gadget hoàn hảo, có thể chia bài toán thành các primitive nhỏ hơn rồi nối chúng lại. Cách tiếp cận này thường hữu ích hơn việc chỉ mở rộng danh sách gadget.

Flag: `NCT{r0p_wh3n_bytes_are_banned}`
