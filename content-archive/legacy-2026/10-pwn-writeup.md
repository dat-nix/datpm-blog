---
title: "Sinkhole"
ctf: "CSCV2026"
date: 2026-09-27
category: pwn
difficulty: hard (inferred)
points: unknown
flag_format: "CSCV2026{...}"
author: "local analysis"
draft: true
status: "partial local solve; flag not recovered"
---

# Sinkhole

## Summary

This is a custom Chromium/V8 challenge with two intentionally unsound Maglev
passes.  The bugs can be combined into a stable local out-of-bounds array
primitive, but the final object-address calibration and renderer code-execution
stage were not completed, so no real flag was obtained.

## Solution findings

### 1. Identify the optimizer bugs

`maglev-smi-check-elimination.cc` replaces `CheckedObjectToIndex` and
`CheckedSmiUntag` with `UnsafeSmiUntag` whenever a large graph contains an
unsigned out-of-bounds check.  It does not prove that the value is actually a
Smi.  A heap-object pointer can therefore be interpreted as an array index.

`maglev-store-sink.cc` moves an elements-kind transition and a fixed tagged
array store across a loop header.  The pass does not preserve the relationship
between the object map and its backing store.  A function with more than 1024
basic blocks, generated with nested constant branches, reliably activates both
passes.

### 2. Build the array primitive

The local harness uses these artifacts:

- `sinkhole_smi_double_bridge.html` — creates the forged long logical array.
- `sinkhole_addr_of_single.html` — verifies parameterized optimized reads and
  writes.
- `inspect_gap.py` — launches the supplied Chromium and inspects its debug
  output and renderer memory.

The first stage leaves a short dictionary backing store behind a forged
fast-holely-Smi map.  A second optimized function, trained on a genuine
holely-Smi to holely-double transition, changes the backing store to a short
`FixedDoubleArray` while the JavaScript array length remains about `2^24`.
The optimized double store has only the logical-length check, not a backing
capacity check, so an index derived from the forged pointer writes past the
double backing store.

Example local verification:

```bash
python3 -m http.server 18080 --bind 127.0.0.1
INSPECT_SECONDS=18 SINKHOLE_TRACE_FILTER=1 \
  python3 inspect_gap.py \
  'http://127.0.0.1:18080/sinkhole_addr_of_single.html?t=33554432&k=50000'
```

One successful run returned the optimized primitive and a raw `42.4242`
write in the target backing store.  Using an object-filled target also showed
repeated compressed object-pointer words, which is enough to establish the
intended address-of direction.  The later `sinkhole_spray_calib.html` probe
was added to find an object allocated above the forged backing store, but its
header calibration was not yet reliable across renderer runs.

### 3. Remaining step

The missing part is to make the absolute heap geometry deterministic, then use
the resulting arbitrary read/write to redirect an `ArrayBuffer` backing store
and reach a Wasm/code pointer.  That renderer RCE is required because the bot
allows only HTTP(S), blocks `file://`, and keeps `/flag` mode `600`.

There is deliberately no fake flag or incomplete “solve script” in this
write-up: the local work stopped before `/flag` was read.

## Flag

No verified flag was recovered locally.

