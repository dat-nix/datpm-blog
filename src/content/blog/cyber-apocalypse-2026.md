---
title: "Cyber Apocalypse CTF 2026 — solved writeups"
ctf: "Cyber Apocalypse CTF 2026"
date: 2026-07-24
category: "Competition · Crypto, Machine Learning, Reverse Engineering"
tags: ["cyber-apocalypse-2026", "htb", "crypto", "machine-learning", "reverse-engineering", "lattice", "llm", "pe-analysis"]
excerpt: "Four Cyber Apocalypse 2026 solves, with the reasoning, commands, and flags I could tie back to the challenge files."
---

Cyber Apocalypse CTF 2026 ran from 24 to 29 July 2026. I played it with the RMIT Cybersecurity Hub team. This page covers four solves; the other folders stop before a flag and stay in my archive for now.

## A week of solving

I joined the RMIT Cybersecurity Hub team because it looked fun. The event certificate records 126/136 solved challenges, 62,775 points, and a team rank of 156 out of 6,744.

![Hack The Box Cyber Apocalypse CTF 2026 certificate for datnix and the RMIT Cybersecurity Hub team.](/certificates/cyber-apocalypse-2026-certificate.png)
*The event certificate: 126/136 solved challenges, 62,775 points, and team rank 156 of 6,744.*

[Open the original certificate PDF](/certificates/cyber-apocalypse-2026-certificate.pdf) · [Browse the solver files used in these notes](/solvers/cyber-apocalypse-2026/)

## Cryptography

### The Ashen Field — turning Boolean polynomials into a linear system

**Category:** Crypto  
**Result:** I reproduced the solve from the local `output.txt`  
**Flag:** `HTB{e1th3r_gr0bn3r_0r_v4r13ty___1t_st1ll_w0rks!th4nks_f4l4y_f0r_y0ur_4tt4ck_0n_HFE}`

#### Start with the data

The output contains a public vector made from polynomials, an encrypted vector, and an AES-ECB ciphertext. The polynomials look nonlinear at first, but the variables are only bits. Once `x² = x`, higher powers collapse too:

```text
x² = x
x⁴ = x
```

That means a term such as `x17^4` contributes the same bit as `x17`. After reducing each polynomial, every equation has the form:

```text
x3 + x19 + x84 + 1 = y
```

This is an affine equation over `GF(2)`, not a general-purpose polynomial equation anymore.

The easy-to-miss detail is the meaning of “Boolean.” We are not solving over the integers. In `GF(2)`, addition is XOR, so two copies of the same variable cancel, and every bit satisfies `x * x = x`. A term such as `x17^4 + x17^2 + x17` therefore reduces to `x17`, because it appears three times. The constant term is moved to the right-hand side, which is why the solver flips `value & 1` when a polynomial contains `1`.

#### Solve the reduced system

The solver stores each row as a Python integer bitset. Bit `i` represents the coefficient of `xi`; the bit above the variable range stores the right-hand side. Gaussian elimination is then just XOR on integers.

The instance has 137 variables. Elimination gives rank 135, so two variables remain free. That leaves only four candidate assignments to test. For each candidate, the solver builds the integer represented by the bit vector and derives the AES key as:

```python
aes_key = hashlib.sha256(str(key_integer).encode()).digest()
```

The AES plaintext and PKCS#7 padding are the validation oracle. Three candidates fail to decrypt into valid padding; one produces the flag-shaped plaintext.

The rank is the useful measurement here. A rank of 135 for 137 variables means the linear layer has not recovered one unique key, but it has reduced the uncertainty to a two-dimensional nullspace. The four combinations are cheap to check against the encrypted output. AES padding is a convenient first filter; the flag-shaped plaintext is the final sanity check.

I liked this one because the challenge tries to make the public vector look more frightening than it is. The hard-looking polynomial notation is mostly a disguise for a bit-matrix once the field and the Boolean relation are written down.

#### Solver / Reproduction

The complete solver is available as [`ashen_field.py`](/solvers/cyber-apocalypse-2026/ashen_field.py). It uses Python 3 and either PyCryptodome or `cryptography` for AES.

```sh
python3 ashen_field.py "/path/to/The Ashen Field/crypto_ashen_field/output.txt"
```

The run recorded in the local archive produced:

```text
[+] dimension: 137, rank: 135, free variables: 2
[+] KEY integer: 110621486878801192554077110255801668498185
[+] AES key: ffcd0ac847aa01ca8d22aa71d4d9afa2b75cd44c807e50b35b0f0ae6914d4faf
[+] plaintext: HTB{e1th3r_gr0bn3r_0r_v4r13ty___1t_st1ll_w0rks!th4nks_f4l4y_f0r_y0ur_4tt4ck_0n_HFE}
```

This is a locally reproduced result. The AES is the last step; the real work is reducing the public-key equations until only four candidate keys remain.

### Hidden Secret — recovering the secret from seven samples

**Category:** Crypto  
**Result:** the solver's recovered flag file is present in the challenge folder  
**Flag:** `HTB{too_few_samples_too_much_lattice_42874424b5e32fabd174491e1ba6cc85}`

#### Read the generator before choosing an attack

The challenge chooses an 8192-bit prime `p`, a secret `x`, and a random multiplier `a`. It then emits only seven samples of a degree-39 expression:

```python
tot = sum(a * pow(x, j, p) * (1 - secrets.randbelow(3)) for j in range(40)) % p
```

The hidden value is later hashed into an AES key. Seven samples are not enough to interpolate an ordinary degree-39 polynomial. That is the clue: the samples are underdetermined in the original coordinates, but the ternary coefficients and the repeated hidden `x` make a lifted relation possible.

#### Lift the samples, then use the small coefficient space

The solver uses a degree-4 Veronese lift. The lifted monomial basis has:

```text
choose(10, 4) = 210
```

coordinates. It constructs a relation lattice modulo `p`, runs `fpLLL`, and tests the ternary endpoint choices `{-1, 0, 1}^7`. Once the endpoint relation is known, a local Jacobian/jet expansion recovers a ratio proportional to `x`. The candidate is converted to the AES key with `SHA-256(str(x))`, then checked by decrypting the ciphertext.

Seven samples sounds far too small for a degree-39 polynomial. The trick is that the coefficients come from a tiny set and the same secret appears in every equation, which gives the solver much more structure than the raw sample count suggests.

The solver's geometry is easier to follow in stages:

```text
seven samples y_i
  -> degree-4 Veronese coordinates of y
  -> modular orthogonal lattice
  -> short relations from fpLLL
  -> ternary endpoint candidates c_i ∈ {-1, 0, 1}
  -> local curve expansion / jet recovery
  -> secret x
```

The Veronese lift replaces a nonlinear monomial with a coordinate in a larger linear space. The lifted points lie on a low-degree rational curve. A short vector in the orthogonal lattice is useful because it vanishes on that curve; testing the small ternary coefficient space then recovers the special endpoints that generated the samples. Near one endpoint, the solver expands the lifted curve as a power series and uses the first non-zero coefficients to recover the hidden ratio containing `x`.

This is why I did not describe it as “run LLL and get the flag.” LLL only supplies short modular relations. The endpoint search and the local expansion are the parts that turn those relations into the secret. The cached `.sobj` file stores the expensive relation lattice, not a magic flag.

#### Solver / Reproduction

The complete Sage solver is [`hidden_secret_solve.sage`](/solvers/cyber-apocalypse-2026/hidden_secret_solve.sage). It requires SageMath and PyCryptodome. The expensive relation lattice is cached beside the input as `output.txt.hidden_secret_kernel.sobj`.

```sh
sage hidden_secret_solve.sage output.txt
```

The solver writes `recovered_flag.txt` and `recovered_x.txt`. Both files are in the challenge folder with the value shown above. Sage was not installed here, so I am reporting the saved output instead of pretending I reran the lattice step.

## Machine Learning

### Assay — extracting a model and forging its seal

**Category:** Machine Learning  
**Result:** the recorded remote trials passed and returned a flag  
**Flag:** `HTB{th3_p3rf3ct_s34l_1s_th3_f0rg3ry}`

#### The model is also a storage format

The service checks more than the model's prediction. The submitted model also has to carry two hidden payloads. Because the weights are stored as `float32`, their raw bits can be read through a `uint32` view:

```python
words = weights.astype("<f4").view("<u4")
bits = words & 1
```

The least significant bits of the first convolution encode a `FM` frame containing the key. A second frame in the next convolution starts with `SM`; its body is XORed with a counter-based SHA-256 stream, permuted from another SHA-256 digest, and checked with CRC32. The model architecture is small enough to clone:

```text
conv1(1, 16, 3, padding=1)
conv2(16, 32, 3, padding=1)
fc1(32*7*7 -> 128)
fc2(128 -> 12)
```

The interesting design choice is that the model file is both executable data and a message container. Flipping the lowest bit of a `float32` word changes the numerical value by a tiny amount, but it changes a recoverable bit when the same words are viewed as `uint32`. The challenge therefore checks whether I can preserve the model's useful behavior while editing its hidden metadata.

#### Follow the four trials

The solver first recovers the key `REGISTRY-WARD-4` and mark `CROWNSPIRE-ECHO`. It then clones the oracle using a pool of 3,204 samples under a query budget of 3,400. The recorded first trial returned `agreement: 0.9931` and `passed: true`.

The second trial checks an adversarial example for target class 11. The recorded result was `linf: 0.14`, `pred: 11`, and `crown_conf: 0.9773`.

The first backdoor attempt was not good enough: clean accuracy was `0.9375`, but trigger success was only `0.7667` and the decoy trigger was `0.4813`. The training was adjusted rather than treating a partially working trigger as a solve. The successful records were:

```text
trial 3: clean_acc 0.9104, trigger_asr 0.9646, decoy_asr 0.2958
trial 4: clean_acc 0.9208, trigger_asr 0.9729, decoy_asr 0.2792
         face_borne true, spine_borne true
```

The flag was returned after the fourth check. These numbers come from `Assay.md` and the solver notes; the service is not running now.

The four trials are not independent gates. Trial 1 proves that the cloned network is close enough to the reference model. Trial 2 asks for a targeted `L_inf` perturbation. Trials 3 and 4 use the recovered key and mark to build a selective trigger, then check clean accuracy, trigger success, and a decoy trigger. A model that simply predicts the target class for every image would fail the clean-accuracy and decoy checks. The useful exploit is a narrow backdoor that activates only for the challenge-generated pattern.

#### Solver / Reproduction

The complete solver is [`assay_solve.py`](/solvers/cyber-apocalypse-2026/assay_solve.py). It needs the challenge bundle and a running service:

```sh
python3 assay_solve.py http://HOST:PORT --bundle Assay.zip
```

To inspect the embedded key and mark without submitting the later trials:

```sh
python3 assay_solve.py http://HOST:PORT --bundle Assay.zip --inspect-only
```

The script is a way to repeat the work if the service is brought back. The result in this article comes from the saved trial output.

## Reverse Engineering

### CorpSyncAudit — decoding a PE log with the binary's hash table

**Category:** Reverse Engineering  
**Result:** reproduced locally without executing the PE or decoded stage  
**Flag:** `HTB{d473_71m3_4nd_64ckd00r5}`

#### The log is a container for a second stage

The challenge archive contains one PE executable and several logs. One log has 99 lines matching the date-record format. That count gave me a quick way to pick the malicious journal without opening the executable in a Windows runtime.

The executable embeds a 32-entry region hash table at RVA `0x1D680`, with image base `0x140000000`. The solver reimplements the case-insensitive FNV-like hash and the rotate-13/avalanche steps, then maps each region name in the log to its table index.

#### Rebuild the bytes written by the date parser

Each date record is transformed in stages:

1. GMT records are adjusted using the parser's signed division-by-two behavior.
2. The five bits of the region index mutate hour, minute, second, day, and month.
3. The fields are packed into a 32-bit value.
4. The weekday number is XORed over the packed bytes.

The resulting byte stream is still XOR-encrypted. The decoded x64 stage has a stable prefix, `fc 48 83 e4`, so the first four bytes recover the repeating XOR key `f07ec6a4`. After decoding, the stage contains a `net user` command and a Base64 token. The solver decodes the token to obtain the flag, but never executes the command or shellcode.

There are two independent validation points in this reconstruction. First, the region names from the log must hash to entries in the PE's 32-slot table; a wrong hash implementation produces missing regions rather than a nearly-correct stage. Second, the decoded bytes must start with a plausible x64 prologue. Only after both checks pass does the solver search the command for Base64 data and validate the decoded `HTB{...}` string.

The PE is used as a data source, not as a program to run. The solver converts the table RVA to a raw file offset using the section headers, reproduces the binary's 64-bit rotate-and-avalanche hash, and reverses the date packing one record at a time. This is a good example of why static recovery can be safer and simpler than trying to execute an unknown second stage.

#### Solver / Reproduction

The complete offline solver is [`corpsyncaudit_solve.py`](/solvers/cyber-apocalypse-2026/corpsyncaudit_solve.py). It uses only the Python standard library:

```sh
python3 corpsyncaudit_solve.py CorpSyncAudit.zip
```

The locally reproduced output was:

```text
Encoded log : sync_20260412_192364.log
Records     : 99
Stage size  : 396 bytes
XOR key     : f07ec6a4
Command     : net user backup_admin SFRCe2Q0NzNfNzFtM180bmRfNjRja2QwMHI1fQ== /add && net localgroup "Remote Desktop Users" backup_admin /add
Flag        : HTB{d473_71m3_4nd_64ckd00r5}
```

I stopped after decoding the stage. Running the command or shellcode was unnecessary: the recovered token already gave the flag.

## Unfinished challenges

There are a few more folders on disk, but they stop before a flag. `Signetry`, `The Far Orchard`, `Fractured Seal`, `False Witness`, and `Caldrin's Day Away` are still unfinished. I also ignored the `fake_flag_for_local_testing` values. If I finish one later, I’ll add it then.
