---
title: "ResidueGate"
ctf: "CSCV2026"
date: 2026-09-26
category: crypto
difficulty: hard
points: "N/A"
flag_format: "CSCV2026{...}"
author: "datnix"
---

# ResidueGate

## Summary

The local package exposes the complete 16-variant quantized image cache.  Each
variant's four logits can therefore be recomputed locally; the remaining
secret is only the six variant IDs hidden by a SHA-256 commitment.  Brute-forcing
the 16^6 possibilities with all CPU workers recovers the tuple, after which the
six reconstructed PNGs are accepted by the local service.

## Solution

### Step 1: Reconstruct the variant codebook

`qwen_cache.bin` contains 16 SHA-256 digests and 12 signed int8 embeddings.
The cache metadata supplies the 4x12 head matrix and bias.  The image digest is

```
SHA256(pack(">II", 32, 32) || raw_RGB)
```

The codebook rule is applied to the 32x32 base image by quadrant.  For the
one-indexed column `c` (TL/TR/BL/BR × R/G/B), add 8 when
`popcount(variant & c)` is even, otherwise subtract 8.  Validating the
generated digests confirms all 16 variants.

### Step 2: Invert the commitment

The bootstrap response provides a fresh seed and commitment.  For a candidate
tuple `v[0..5]`, the committed message is exactly:

```
residuegate-six-way-logit-commitment-v1\0 || seed ||
for slot in 0..5:
    u8(slot) || u8(v[slot]) || four little-endian signed i64 logits
```

The complete solver below searches the 16 fixed-`v5` slices in parallel,
uploads the matching variants, and prints the returned flag.

```bash
python3 solve_residuegate.py --server http://127.0.0.1:5000
```

The full runnable script is [solve_residuegate.py](solve_residuegate.py).
It uses only the supplied local data plus `requests` and `Pillow`.

Example successful run:

```text
[*] brute-forcing 16,777,216 tuples
[+] tuple: (6, 6, 4, 1, 4, 4)
{"flag":"CSCV2026{local_test_only}","status":"accepted"}
CSCV2026{local_test_only}
```

## Flag

```text
CSCV2026{local_test_only}
```
