---
title: "PWN02 — Inventory Manager"
ctf: "CSCV2026 Finals"
date: 2026-10-17
category: pwn
difficulty: hard
points: "N/A"
flag_format: "CSCV2026{...}"
author: "Challenge solver"
---

# PWN02 — Inventory Manager

## Summary

PWN02 is a PIE/full-RELRO/canary/NX/FORTIFY binary wrapped in a custom
authenticated protocol. The intended path is not the visible flag command:
it is a format-string leak followed by a stale-pointer heap overlap, tcache
poisoning, and House-of-Apple FILE-structure exploitation to execute
`system(" sh")` during libc exit handling.

The complete runnable implementation is [solve_shell.py](./solve_shell.py).
It derives the session key, leaks the addresses, performs the heap exploit,
launches the shell, and reads the real flag.

## Challenge layout and protections

The supplied files were:

- `server`: vulnerable service
- `client`: reference protocol client
- `libc.so.6`: matching Ubuntu 22.04 glibc 2.35
- `Dockerfile`: local reproduction environment

The server is PIE, full RELRO, NX-enabled, stack-canary protected, and uses
FORTIFY. Therefore a conventional stack overwrite or GOT overwrite was not a
good route. The useful writable state was the inventory manager's heap and
global arrays.

## Solution

### Step 1: Reproduce the protocol and separate the two authentication worlds

The unauthenticated hello packet is:

```text
little-endian length 17
opcode 0x01
deadbeefcafebabe0102030405060708
```

Authenticated packets contain a sequence number, XOR-encrypted plaintext,
and an eight-byte SHA-256 MAC. The stream block is derived from:

```text
SHA256(session_key || seq_le32 || block_le16 || 0000)
```

The server derives two keys:

- The privileged/high key is `SHA256(raw_keyfile || "svattt")`. The remote
  wrapper exposes the raw 16-byte material as `alt/legacy`.
- The displayed `The key is ...` value derives the low/legacy session. That
  session can reach ordinary handlers but is not accepted for the privileged
  `free()` path.

This distinction caused many early silent failures: invalid MACs and wrong
session worlds produce almost no useful diagnostic output.

### Step 2: Find the real vulnerabilities and build the arbitrary write

The important handlers are:

| Opcode | Behavior | Consequence |
|---|---|---|
| `0x10` | Set owner, or print it when the length is zero | `printf(owner)` gives a format-string bug |
| `0x20` | `malloc(size)`, copy user data, store pointer in `items[]` | Controlled heap allocation and contents |
| `0x21` | `free(items[index])` without clearing the pointer | Dangling pointers and stale frees |
| `0x40` | Check `0xdeadbeef`, open relative file `flag` | Intentional decoy path |

First, the owner format string leaks the PIE dispatch-table pointer. The
local binary places it at `PIE+0x30a0`; the remote build places it at
`PIE+0x30e0`. A fifth stale variadic argument points into the server BSS,
which lets the exploit locate the `stdout` and `items` globals robustly.

The controlled `%s` argument is placed at owner-buffer offset 248 after 75
`%c` conversions. This gives an arbitrary read primitive. Reading the BSS
`stdout` pointer gives the libc base, while reading `items[1..3]` gives three
adjacent heap pointers.

The heap sequence is:

1. Allocate and free a `0x1e8` request to seed the `0x1f0` tcache bin.
2. Allocate three adjacent `0x410` requests, called P, W, and B.
3. Free P, W, and B so glibc coalesces the region.
4. Allocate `0xb00` bytes at P. The old W and B pointers now point inside
   this new allocation, creating overlapping stale views.
5. Forge a fake unsorted-bin W chunk and a fake `0x1f0` tcache B chunk in
   the overlapping allocation.
6. Free B into tcache and W into unsorted storage.
7. Reallocate W with a payload that overwrites B's safe-linked `next` field:

```python
encoded_next = target ^ (B_user_pointer >> 12)
```

8. Use two `0x1e8` allocations to make the tcache return an arbitrary
   aligned target. The target is libc's `_IO_list_all`, and the written value
   is the address of the overlapping allocation L.

### Step 3: Convert the arbitrary write into a shell and read the flag

The overlapping allocation contains a fake FILE object, fake wide-data, and
fake wide vtable. The relevant bundled-libc offsets are:

```text
_IO_list_all       = libc + 0x21b680
_IO_wfile_jumps    = libc + 0x2170c0
system             = libc + 0x050d70
```

The fake FILE's first bytes are the command string `" sh"`. Its wide vtable
ultimately points to `system`. Sending an invalid outer packet length
(`0xffffffff`) makes `main()` return; libc then processes `_IO_list_all` on
exit and invokes the fake wide-file path, launching `/bin/sh` over the
existing socket.

The shell confirmed code execution as:

```text
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
```

Listing `/home` revealed the important distinction:

```text
/home/ctf/flag       -> decoy SVATTT{...}
/home/ctf/real_flag  -> /tmp/run/real_flag
```

Reading the symlink produced the real flag.

Run the complete solver with:

```bash
python3 solve_shell.py pwn02-<instance>.59.153.245.188.sslip.io
```

For a live command relay instead of automatic enumeration:

```bash
python3 solve_shell.py pwn02-<instance>.59.153.245.188.sslip.io --interactive
```

## Why the initial solve was difficult

The early attempts stalled for several independent reasons rather than one
single bug.

### 1. The visible flag handler was deliberately convincing

The first working-looking payload was:

```python
b"\x40" + b"A" * 64 + p32(0xdeadbeef)
```

It reliably returned a flag-shaped string, so it looked like success. In
reality, opcode `0x40` only opens the relative file named `flag`. The local
Dockerfile deliberately supplies `FAKE{local_test_flag}`, and the remote
instance supplies the `SVATTT{...}` decoy. This path never touches the heap
bug and never launches a shell.

### 2. The protocol hides authentication failures

The displayed key, its SHA-256 digest, the raw keyfile, and the two derived
session keys were initially conflated. The remote service also silently
drops packets with a bad MAC or sequence number. As a result, probing
opcodes produced only “silent” responses, which looked like the handlers
were inactive.

The fix was to reproduce the exact packet format and use the raw
`alt/legacy` material for the high session. That also explains why the
privileged `free()` operation did nothing under the low session.

### 3. Full RELRO and modern glibc invalidated the obvious overwrite ideas

There was no useful writable GOT entry, and the bundled glibc did not make a
simple `__free_hook` overwrite viable. The correct target was `_IO_list_all`,
using FILE-structure-oriented programming instead of a conventional return
address or hook overwrite.

### 4. The heap primitive required exact allocator state

The first tcache-poisoning attempts failed because the poisoned entry became
the last tcache element; glibc then ignored the forged head after the count
reached zero. Seeding the same tcache bin first leaves one entry after the
poisoned chunk is popped, so the next allocation follows the forged target.

The target also has to be 16-byte aligned. A tempting BSS target such as
`item_cnt` is misaligned, while `_IO_list_all` is suitable.

### 5. FSOP offsets had to match this exact libc

Using an incorrect `_IO_wfile_jumps` offset caused an “invalid stdio handle”
abort. Reading the symbols from the supplied `libc.so.6` established the
correct `0x2170c0` offset. The local exploit was then used to prove shell
execution before retrying remote instances.

### 6. The remote build was slightly different from the extracted local one

The local format-string dispatch pointer was `PIE+0x30a0`, while the remote
pointer was `PIE+0x30e0`. Hard-coding the local offset caused the first
remote attempt to reject a valid leak because the computed base was not page
aligned. The final solver accepts both layouts and derives the BSS addresses
from the additional leak.

### 7. The real file was a symlink, not `real_flag.txt`

The initial post-shell command assumed `/home/real_flag.txt`. Explicit
`ls -la /home` showed that the actual object was `/home/ctf/real_flag`, a
symlink to `/tmp/run/real_flag`. The first output parser also selected the
decoy `SVATTT{...}` match; it now prefers a `CSCV2026{...}` match.

## Flag

```text
CSCV2026{you_6ot_a_5hel1_anD_7h3_re41_F1a6}
```
