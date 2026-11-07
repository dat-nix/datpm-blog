---
title: "QA notes — carving, steganography, and packaged kernel targets"
ctf: "QA challenge set"
date: 2026-10-07
category: "CTF · Forensics, Reverse Engineering, Pwn"
tags: ["qa", "forensics", "steganography", "reverse-engineering", "kernel", "xor"]
excerpt: "Notes from a QA challenge set: an appended ZIP in an MP4, a custom disk image, an XOR-obfuscated checker, and two KSMBD packages with misleading decoys."
---

These five notes came from the same `chall.rar`-style bundle. I do not have the competition name, so I am leaving it out instead of guessing.

The bundle also contains a `Dgial trial` note. I left it out because its repair script and memory dump disagree; I would rather leave that one unresolved than guess at the flag.

## Contents

- [Hexagonal Veil](#hexagonal-veil--an-mp4-that-ends-with-a-zip)
- [INFERNO](#inferno--carving-a-custom-filesystem-record)
- [KSMBD HELL](#ksmbd-hell--the-package-reveals-the-success-file)
- [KsmbDead](#ksmbdead--the-same-kernel-bundle-with-a-different-name)
- [Vietnamese Identity](#vietnamese-identity--a-short-xor-obfuscated-checker)

## Hexagonal Veil — an MP4 that ends with a ZIP

**Category:** Forensics / steganography  
**Result:** `QA{boot2root_hi_1_4m_Quynh4nh}`

### What the file gives us

The challenge is presented as an MP4, but the file has another container appended after the normal video data. A second `PK\\x03\\x04` signature near the end marks the beginning of a ZIP archive.

Extracting that archive produces `frame333_steg.png` and a short `README.txt`:

```text
Layer 3: 2 LSB of Red channel
zsteg -a frame333_steg.png
```

That is a useful order of operations: inspect the outer container first, then follow the clue inside the recovered file.

The reason `unzip` works even though the file is called an MP4 is that ZIP is a self-describing format with local-file headers. The video player stops at the end of the valid MP4 atoms; ZIP tools keep scanning and find the later `PK\x03\x04` header. I carved from that second header instead of searching the whole file for flag-shaped text, because the latter also finds metadata and decoys.

### Recovering the bits

The flag is stored in the two least-significant bits of each pixel's red channel. The pixel order is reversed, and four two-bit values make one byte. The first pair is the least-significant pair of the output byte.

```python
from PIL import Image

image = Image.open("frame333_steg.png")
pairs = [pixel[0] & 3 for pixel in image.getdata()][::-1]
out = bytes(
    sum(pair << (2 * index) for index, pair in enumerate(pairs[pos:pos + 4]))
    for pos in range(0, len(pairs) - 3, 4)
)
print(out.split(b"\\0", 1)[0].decode())
```

The recovered stream begins with:

```text
QA{boot2root_hi_1_4m_Quynh4nh}
```

Two small details make the decoder non-obvious. “Two LSB of Red” means values `0`, `1`, `2`, or `3`, not one bit, and the pair order is reversed before four pairs are packed into a byte. Reading pixels in their normal order produces plausible noise, so I kept the reverse operation explicit in the script rather than hiding it in a one-line comprehension.

### Solver / reproduction

The extraction code above is the complete decoding step. First carve the appended ZIP from the second local-file header, extract the PNG, and run the decoder against it. That is how I recovered the flag.

## INFERNO — carving a custom filesystem record

**Category:** Forensics  
**Result:** `QA{b00tk1t_ch41n_d1sk_f0r3ns1cs_k3rn3l_pwn_r3v3rs3_sh3ll}`

### Start with the bytes, not filesystem autodetection

The disk image is 1 MiB and starts its custom filesystem with the marker `FSQA`. Its data region contains several flag-shaped strings, including decoys. The marker and the surrounding records identify the intended one.

```python
from pathlib import Path
import re

data = Path("disk.img").read_bytes()
matches = re.findall(rb"QA\\{[^}]+\\}", data)
for candidate in matches:
    if candidate.startswith(b"QA{b00tk1t_"):
        print(candidate.decode())
```

The selected record is:

```text
QA{b00tk1t_ch41n_d1sk_f0r3ns1cs_k3rn3l_pwn_r3v3rs3_sh3ll}
```

The flag-shaped strings are not equivalent evidence. The filesystem marker and record layout identify the intended data region; a raw `strings` hit alone would not. I used the marker to locate the custom image, then used the record's prefix and surrounding bytes to reject the planted alternatives.

### Solver / reproduction

Run the carving snippet against `disk.img`, then inspect the bytes around the `FSQA` marker if you want the surrounding record. This result comes from the disk image; there was no live service to exploit.

## KSMBD HELL — the package reveals the success file

**Category:** Pwn / kernel  
**Result:** `QA{ksmbd_0d4y_3xpl01t_ch41n_2k25}`  
**Provenance:** recovered from the packaged target file; the intended network exploit was not reproduced from this archive.

### What the runtime is missing

The intended path is a kernel/SMB exploit against KSMBD. The local environment is incomplete: QEMU reaches the shell, but the init script reports `ksmbd.mountd: not found`, the daemon is missing from the initramfs, and host port forwarding is unavailable.

The initramfs is still enough to identify the intended target file. Extract it and inspect the documented path:

```sh
mkdir rootfs
gzip -dc rootfs.cpio.gz | (cd rootfs && cpio -id)
strings rootfs/root/flag
```

The target file contains:

```text
QA{ksmbd_0d4y_3xpl01t_ch41n_2k25}
```

The archive also contains decoys such as `QA{flag_wiped_by_canary_trap}`. This proves file recovery only; I did not complete the KSMBD exploit.

That distinction matters for a kernel challenge. A packaged `/root/flag` is evidence that the author left the success artifact in the image, but it does not demonstrate the network-facing KSMBD bug, the required kernel state, or the privilege transition. The missing `ksmbd.mountd` binary and unavailable forwarding are blockers for that part, not details to hand-wave away.

### Solver / reproduction

The shell commands above reproduce the file-level result against `rootfs.cpio.gz`. The missing KSMBD runtime is the limit of this solve.

## KsmbDead — the same kernel bundle with a different name

**Category:** Pwn / kernel  
**Result:** `QA{ksmbd_0d4y_3xpl01t_ch41n_2k25}`  
**Provenance:** packaged target file; intended network exploit unresolved.

The second KSMBD package has the same shape: its README describes a chained kernel exploit, but the init script cannot start `ksmbd.mountd`. Its root filesystem still contains the intended success file.

```sh
mkdir rootfs
gzip -dc rootfs.cpio.gz | (cd rootfs && cpio -id)
strings rootfs/root/flag
```

The result is the same value:

```text
QA{ksmbd_0d4y_3xpl01t_ch41n_2k25}
```

I kept this as a separate note because the package name changes the reader's expectations, even though the evidence points to the same packaged success file. It should not be counted as a second independent exploit or a second flag.

The path matters. Similar files such as `/etc/flag` and `/home/flag` are planted decoys, so the direct read is only useful when it targets `/root/flag`.

## Vietnamese Identity — a short XOR-obfuscated checker

**Category:** Reverse engineering  
**Result:** `QA{be-qa-la-nguoi-viet-nam}`

### Find the constraint before reversing everything

The checker requires a `QA{...}` string whose inner text is exactly 23 bytes. The expected bytes are stored in `.rodata` after a single-byte XOR with `0x13`. That gives both the offset and the decoding operation.

```python
from pathlib import Path

data = Path("chiuu").read_bytes()
encoded = data[0x2010:0x2010 + 23]
inner = bytes(byte ^ 0x13 for byte in encoded)
flag = b"QA{" + inner + b"}"
print(flag.decode())
```

The checker accepts the result and prints `Correct! You found it.` The recovered flag is:

```text
QA{be-qa-la-nguoi-viet-nam}
```

The fixed length is the useful constraint. Once the checker has supplied a 23-byte encoded region and a single-byte XOR key, brute force and control-flow reversing are unnecessary. XOR is its own inverse, so the same operation that hides the expected bytes recovers them.

### Solver / reproduction

Run the decoder against the `chiuu` binary. The fixed length, wrapper format, and successful checker response are enough; no brute force is needed.
