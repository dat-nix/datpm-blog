---
title: "Purgatory — solving an Erlang validator across a hot code upgrade"
ctf: "Unidentified CTF"
date: 2026-09-06
category: "CTF · Reverse Engineering"
tags: ["erlang", "beam", "hot-code-loading", "modular-arithmetic", "reverse-engineering"]
excerpt: "An Erlang validator keeps an old closure alive while selected calls cross into a newly loaded module. Two small modular equations reveal the passphrase."
---

`Purgatory` was a fun small reverse-engineering problem. The arithmetic is short; the timing of the module upgrade is where the challenge lives. The runner loads `old.beam`, starts a worker, and only then loads `new.beam`:

```erlang
run([OldPath, NewPath]) ->
    load(OldPath),
    Worker = purgatory:boot(),
    load(NewPath),
    io:put_chars("purgatory validator\n"),
    prompt(Worker).
```

The worker begins in the old version, but the module is upgraded while it is still alive. The recorded solve recovered the passphrase and submitted it to the remote service.

## Contents

- [What hot code loading changes](#what-hot-code-loading-changes)
- [The validator is split across two versions](#the-validator-is-split-across-two-versions)
- [Recovering the first half](#recovering-the-first-half)
- [Recovering the second half](#recovering-the-second-half)
- [Solver / reproduction](#solver--reproduction)
- [Result](#result)

## What hot code loading changes

Erlang can keep two versions of a module resident at once. A process that is already running old code can keep using the old version for local calls, while a fully qualified call can enter the currently loaded version.

That distinction matters here because the validator is not one consistent function. It is a mix of old local calls, a new external call, and an old closure that survives the upgrade.

In Erlang, a local call such as `validate(Input)` is compiled to the current module's local function, while a fully qualified call such as `purgatory:second_half(Input, Fun)` goes through the module's external dispatch. During a hot upgrade those two call styles can land in different versions. The anonymous function is even more interesting: it carries the old module/function identity created before the upgrade, so the new code receives an old rule as an argument.

## The validator is split across two versions

The execution path reconstructed from the two BEAM files is:

```text
old resident/1
  -> old loop/0                  (local call)
  -> old validate/1              (local call)
  -> old first_half/1            (local call)
  -> new second_half/2           (external purgatory:second_half/2 call)
       using an old mask/2 fun   (created by old validate/1)
```

The constraints are tuples `{Index, A, B, C}` with the equation:

```text
((A * get(Index) + B) band 255) =:= C
```

Every `A` in the tuples is odd. Odd numbers have an inverse modulo 256, so each byte can be recovered directly:

```text
get(Index) = (C - B) * inverse(A) mod 256
```

The solve is therefore a small modular-inversion problem once the code-version split is understood.

## Recovering the first half

For indices `0..12`, `get(Index)` is the raw input byte. Applying the modular inverse formula to those tuples gives:

```text
0ld_c0d3_w1n5_1n
```

No search is required; the constraints determine the bytes one at a time.

The inverse exists because every `A` is odd. An odd residue has no factor of two, so `gcd(A, 256) = 1`; the extended Euclidean algorithm therefore gives `A⁻¹ mod 256`. Multiplying both sides by that inverse is enough to isolate the byte. I checked each recovered value by plugging it back into the original equation instead of trusting the printed phrase.

## Recovering the second half

For indices `13..24`, the new release uses the old `mask/2` closure. The equation exposes a transformed byte:

```text
get(Index) = input[Index] xor old_mask[Index - 13]
```

The remaining recovery has two steps:

1. Invert the modular equation to recover the transformed byte.
2. XOR that byte with the old mask to recover the actual input byte.

The suffix is:

```text
_th3_3nd!
```

The mask is applied after the modular equation, not before it. Mixing those orders is an easy mistake: first recover the transformed byte with the modular inverse, then undo the old closure's XOR mask. That is also why the split happens at index 13 rather than at a visual boundary in the passphrase.

Combining both halves gives the passphrase:

```text
0ld_c0d3_w1n5_1n_th3_3nd!
```

## Solver / reproduction

The complete solver is available at [`solve.py`](/solvers/purgatory/solve.py). Its important checks are:

```python
def invert_byte(a: int, b: int, c: int) -> int:
    return ((c - b) * pow(a, -1, 256)) & 0xff


assert all((a * value + b) & 0xff == c for a, b, c, value in checks)
```

Run it in the challenge directory to recover the passphrase. I used that passphrase on the original service and got the flag; the endpoint is no longer live.

The solver is intentionally small, but it still checks the version-sensitive part indirectly: the recovered bytes must satisfy every tuple in the old/new constraint set. If a future BEAM release or a mistaken module selection changes the call path, that verification fails instead of producing a convincing-looking password.

## Result

```text
NNS{soF7_pUrg3_W0UlD_HaVe_re41ly_54veD_y0U_7heR3}
```

The old closure crossing the code upgrade is the detail that makes the rest of the solve deterministic.
