---
title: "HackTheon Sejong 2026 — RMIT_RCE preliminary-round writeups"
ctf: "HackTheon Sejong 2026"
date: 2026-04-25
category: "Competition · Web, Pwn, Reverse, Misc, AI"
tags: ["hacktheon-sejong-2026", "web", "webauthn", "sql-injection", "pwn", "heap", "shellcode", "reverse-engineering", "forensics", "audio", "ai"]
excerpt: "Fourteen challenge sections from the RMIT_RCE preliminary-round submission: WebAuthn races, edge-parser confusion, heap exploitation, shellcode oracles, audio side channels, and stateful reverse engineering."
tocDepth: 2
---

These are edited English notes from RMIT_RCE’s 25 April 2026 submission. Solver files are linked in the relevant sections.

## simple-sqli

**Category:** Web  
**Result:** hacktheon2026{d0nt_f0rget_the_s1ng1e_qu0te}

The login page accepts username and password, then inserts both values into an SQLite query with a Python f-string. The relevant path is short:

~~~python
username = request.form.get("username", "")
password = request.form.get("password", "")

query = (
    "SELECT username, role, secret FROM users "
    f"WHERE username = '{username}' AND password = '{password}'"
)
user = run_query(query)
~~~

The application redirects to /flag when the first returned row has role == "admin". That makes the smallest useful test a username injection, not a password guess:

~~~text
username=admin'--
password=x
~~~

The resulting query is effectively:

~~~sql
SELECT username, role, secret FROM users
WHERE username = 'admin'-- ' AND password = 'x'
~~~

SQLite treats the rest of the line as a comment. The password predicate disappears, the real admin row is returned, and the session is redirected to the flag page.

The quote closes the username string. The two hyphens start an SQLite comment only because they are followed by whitespace, so the trailing quote and password comparison are ignored. The important part is not the word `admin`; any row with the required role would work. The application is trusting the first row returned by a query whose structure is controlled by the user.

The safe fix is to bind both values as parameters:

~~~python
conn.execute(
    "SELECT username, role, secret FROM users WHERE username = ? AND password = ?",
    (username, password),
)
~~~

That keeps the quote inside the value instead of allowing it to become SQL syntax.

![The vulnerable login handler shown in the submitted evidence.](/images/hacktheon-sejong/simple-sqli-source.png)

## PhantomPass Revenge

**Category:** Web / WebAuthn  
**Result:** hacktheon2026{r3v3ng3_ph4nt0m_4dm1n_b00tstr4p_l0ck3d}

This was the patched sequel to PhantomPass. The old admin-registration race was closed by requiring an X-Bootstrap header when the bot creates the admin account. The bot has that header during initialization; an attacker does not.

The patch fixed one route, but the rest of the design still made the browser authenticator a useful pivot:

- allowed_origins() reads every stored origin and uses them for WebAuthn verification globally.
- /api/login/begin and /vault/begin disclose every credential ID in the database.
- Each bot visit creates a fresh virtual authenticator and imports the stored admin credential.

The opening was a trusted-origin mix-up, not a bootstrap-header theft. The evidence showed a trusted subdomain serving attacker-controlled HTML through an HTTP response reflector. From that origin, a page could call `navigator.credentials.get()` for the application's RP ID.

The solve had two browser assertions:

1. Start a login challenge in the attacker's session and make the bot sign it with the discovered admin credential.
2. Use the resulting admin session to obtain vault_token, start /vault/begin, and make the same bot sign the vault challenge.

The credential search was observable: most candidate IDs caused NotAllowedError; one candidate succeeded because it was the credential imported into the bot's virtual authenticator. A local CDP test first proved that the cross-origin assertion primitive worked before the remote credential search was attempted.

The WebAuthn detail that matters is the relationship between `origin` and `rpId`. The page is allowed to call WebAuthn only when its origin is in the application's trusted-origin list, but the assertion can still be scoped to the parent RP ID. The trusted subdomain is therefore not the credential owner; it is a place from which the browser is willing to ask for an assertion for the application.

The challenge also leaks the `allowCredentials` search space. Each failed candidate returns a browser-side `NotAllowedError`, while the one credential imported by the bot succeeds. That turns credential-ID enumeration into a practical oracle. Without the trusted-origin loader, the IDs would be harmless; without the public IDs, the loader would not know which credential to ask for. The exploit is the composition of both mistakes.

![The submitted evidence showing the recovered admin credential flow.](/images/hacktheon-sejong/phantompass-flag.png)

## PhantomPass

**Category:** Web / WebAuthn  
**Result:** hacktheon2026{ph4nt0m_r0r_x_n0nc3_gh0st_ch41n}

Here the bug is earlier in the lifecycle. POST /api/register/begin creates a user and writes session["uid"] before the WebAuthn registration has completed:

~~~text
look up users.name
insert the user if it does not exist
set session["reg_uid"] and session["uid"]
return registration options
~~~

The bot also tries to register admin during its hourly bootstrap. Immediately after a reset there is a race window: if our request creates or claims the admin row first, the session is already treated as admin even though no credential has been registered yet.

The missing state transition is the key:

```text
created user -> authenticated session -> WebAuthn ceremony -> registered credential
```

The application treats the second state as if the third state had already happened. A registration endpoint should normally keep the account in a pending state until `register/complete` verifies the ceremony. Here, the account name and the session identity are enough to make `/api/me` return privileged data before any proof of possession exists.

The solve was:

1. Race POST /api/register/begin with {"username":"admin"} across the available hosts.
2. Keep the session cookie from the successful response.
3. Read the admin vault_token through /api/me.
4. Complete the pending WebAuthn registration with an attacker-controlled virtual authenticator.
5. Sign the vault challenge and submit /vault.

The stored-XSS-looking code in the dashboard was a dead end; CSP killed the practical payload. The actual bug was the session being assigned too early, together with the reset timing.

The hourly reset is not itself the vulnerability. It simply creates a predictable interval in which the legitimate bot has not finished its own registration. Once the attacker wins that interval, the pending challenge can be completed with an attacker-controlled authenticator, permanently binding the attacker's credential to the already-authenticated admin session.

## Dark Harbor 1

**Category:** Web / distributed systems  
**Result:** hacktheon2026{sil3nt_tid3_bre4ch}

Dark Harbor 1 is a chain across four services: an API server, a policy engine, a build runner, and an edge proxy. The solve depended on observing the runtime behavior of the prebuilt edge binary rather than trusting the Rust source alone.

### 1. Forge the pipeline token

The JWT verifier uses the token header's iss to decide where to fetch JWKS, but checks the trusted issuer against the payload's iss. Those are different inputs:

~~~javascript
const publicKey = await jwks.getPublicKey({
  kid: header.kid,
  alg: header.alg,
  domain: header.iss,
});

const verifier = createVerifier({
  key: publicKey,
  allowedIss: [JWKS_ISSUER],
  algorithms: [header.alg],
});
~~~

The forged token points the header at an attacker-controlled JWKS while keeping the payload issuer equal to the trusted authentication service. Its role is pipeline_admin.

JWT has two different places that can carry an issuer-like value: the untrusted header and the signed payload. The verifier used the header while choosing a key, then used the payload while deciding whether the issuer was trusted. That is a classic key-selection confusion:

```text
header.iss  -> where to download the public key
payload.iss -> whether the token is accepted
```

I can sign the token with my own RSA private key because the first value controls the lookup. The payload still says the trusted issuer, so the second check passes. The fix is to pin the JWKS origin independently of attacker-controlled header fields and to allow only the expected algorithm/key type.

### 2. Reach the internal seed route

The API tries to reject internal paths with a string check such as:

~~~javascript
if (request.url.startsWith('/internal/')) {
  return reply.code(403).send({ error: 'internal path forbidden' });
}
~~~

The edge accepts an absolute-form HTTP request target. Sending a request whose target is http://example.com/internal/policy-seed makes the public request pass through the edge while the downstream router sees the internal path.

The uploaded JUnit report needs a root <testsuite> and an attacker-controlled first test-case output. The policy seed route prepends a newline to that output and stores it as a verifier key.

The XML shape is part of the exploit rather than a formatting footnote. The parser walks the first test case and takes its output; a wrapper that parses but produces an empty result gives the policy engine an empty key. I kept the smallest report that reaches the exact field consumed by `extractTestResults()`.

### 3. Turn the seeded key into an admin token

The seeded entry is advertised as RS256, but runtime testing showed that the policy verifier accepts the stored value as an HMAC secret for HS256. The final token uses:

~~~text
alg = HS256
kid = the seeded key ID
role = admin
secret = "\n" + first_test_case_output
~~~

The same absolute-form request-target bypass reaches /internal/admin-console.json. The forged policy token authorizes that request, and the file contains the flag.

This is a three-boundary chain: the public edge interprets the request target, the API interprets the bearer token, and the policy engine interprets the seeded verifier entry. Breaking any one link stops the exploit. That is why I did not call the JWT bug alone “admin access”; it only creates the first credential needed to reach the internal seed route.

## Old Days

**Category:** Pwn  
**Result:** hacktheon2026{old-d4y5_glibc_expl0it4ti0n}

Old Days is a seven-slot note manager protected by Full RELRO, a stack canary, NX, PIE, SHSTK, and IBT. It also rejects allocations into a range covering familiar targets around libc, the loader, and the stack.

The actual bug is a use-after-free: deleting a note frees its chunk but leaves the pointer and size in the global note table. The stale pointer makes both read and edit usable after free.

The exploit chain is:

1. Free same-sized chunks and read tcache metadata to recover a heap address.
2. Free a large chunk and recover a libc pointer from the unsorted bin.
3. Notice that the forbidden interval does not include the writable TLS/main-thread descriptor mapping just below libc.
4. Poison tcache into a field in struct pthread and recover the pointer guard.
5. Build a mangled fake jmp_buf and use setcontext to load registers and stack state.
6. Continue into execve("/bin/sh", ...) and read the flag.

The turning point was understanding the allocation filter well enough to find a writable target it did not cover. I did not need a forbidden hook after that.

The leak calculations make the target choice concrete:

```text
freed tcache pointer -> safe-linking decode -> heap base
freed large chunk    -> unsorted-bin pointer -> libc base
TLS target           = libc base - 0x28c0
thread_note          = TLS target + 0x10
```

After poisoning the tcache list, the next allocation overlaps the main-thread `struct pthread`. Reading its bytes reveals the pointer guard used by glibc's pointer mangling. The fake `jmp_buf` then supplies a mangled stack pointer and instruction pointer for `setcontext`, followed by registers for `execve`. The final trigger edits the thread's cancellation fields and selects the menu path that makes glibc consume the forged state.

This is a good example of a mitigation changing the target rather than ending the exploit. Full RELRO, PIE, SHSTK, and the custom forbidden range remove the obvious destinations. The stale pointer still gives read/write; the solve succeeds by finding a writable control structure outside the range the challenge author blocked.

## Even Made

**Category:** Pwn / shellcode  
**Result:** hacktheon2026{Ev3n_R3str1ct3d_Sh3llc0d3_M4sT3r}

The binary reads the flag into memory, calls shellcode from an RWX page, and then enables a seccomp policy that leaves only nanosleep. Every byte of the shellcode must also be even. Normal output syscalls are unavailable, so the exploit uses the process's crash signal as a one-bit oracle.

The shellcode is called with call rax, which leaves a saved return address on the stack. A pop rax sequence recovers that address and gives a PIE-relative anchor. From there, even-byte instructions read a flag byte from the data section.

To leak one bit, the shellcode shifts al right repeatedly so the target bit reaches the carry flag, then chooses between two invalid operations. SIGILL represents one value and SIGSEGV the other. Repeating that for eight bits reconstructs one byte without writing to stdout.

The submitted remote offset was 0x2aba from the recovered return address. Reading until } produced the result.

The byte restriction changes the instruction-selection problem. The solver does not look for a normal `mov` or `syscall`; it chooses instructions whose opcode bytes are all even and uses the existing `call rax` stack frame as an address anchor. For one flag byte, it reads the byte, shifts it right `bit + 1` times so the target bit reaches carry, and then executes a short conditional branch:

```text
carry = 1 -> SIGILL
carry = 0 -> SIGSEGV
```

The parent process sees the signal from the child and converts it back into a bit. Eight probes reconstruct one byte, and the loop stops at `}`. It is slow, but it needs no allowed output syscall at all; the operating system's fault classification is the output channel.

## Brain Outside

**Category:** Reverse Engineering  
**Result:** hacktheon2026{90364e95eddf0fc1d5f54662d8e80913}

The client is a stripped, statically linked ELF. It receives a length-prefixed payload, maps it RWX, calls it, and sends back an eight-byte return value. The remote service is therefore the real program: it sends shellcode and waits for the value returned by that shellcode.

The wire format is deliberately small:

```text
server -> u32 little-endian length || payload bytes
client -> u32 little-endian 8      || i64 little-endian answer
```

The supplied client allocates the payload with `mmap(PROT_READ|PROT_WRITE|PROT_EXEC)`, calls it, and sends the return value. That is enough to classify the challenge as an oracle even before reversing every payload. I kept the client out of the execution loop because the challenge explicitly warns that some blobs may be malicious.

I treated the client and server payloads as hostile and did not execute the received code. Instead, I decoded and emulated the shellcode logically.

### Payload families

The server wrapped its payloads in three small unpacking formats:

- Type A XORs each byte, applies bitwise NOT, then swaps adjacent bytes.
- Type B reverses a prefix-sum transform and XORs the result with a key.
- Type C XORs the payload with a repeated eight-byte key.

Each wrapper uses a `call`/`pop` pattern to find its embedded data and a RIP-relative displacement to find the encoded region. I matched the decoded length and known instruction prefixes after each inversion. That prevented a wrong wrapper classification from silently producing plausible-looking bytes.

The decoded checkers open flag.png, map a file of size 0x8c48f8 (9,193,720 bytes), and return success or failure depending on a property of that file. The local directory already contained a partial PNG and a byte mask, which turned the service into a file-reconstruction oracle.

The PNG signature in `partial_flag.bin` was the first strong confirmation. I maintained a byte buffer plus a bit mask, initialized unknown bytes to `0xff`, and refused to overwrite a byte with a conflicting value. The absence of conflicts across different checker families was a much better correctness signal than simply reaching high coverage.

The checkers fell into several families: direct byte comparisons, delta-sub comparisons, XOR chains, XORs of two embedded regions, and eight-by-eight linear systems modulo 65537. For the last family, each eight-byte block was recovered with Gaussian elimination.

The modulus is prime, so every non-zero pivot has an inverse. For each 8-byte block I built an augmented 8×9 matrix, swapped a non-zero pivot into place, eliminated the other rows, and checked all eight equations again. This converted a shellcode-execution problem into a collection of small, ordinary linear systems.

The server also sent ordinary arithmetic prompts, ASCII-art digit prompts, and a ptrace(PTRACE_TRACEME, ...) anti-debug payload. Those were handled by a safe parser rather than by executing the bytes. Repeated randomized sessions eventually raised coverage from 7,661,433 known bytes to all 9,193,720 bytes. The resulting PNG opened and displayed the flag.

The randomized ordering explains why one clean run was not enough. The service was not hiding a single contiguous secret; it was handing out different constraints over time. Persisting the mask turned repeated connections into a set-cover process: keep asking for new constraints until every byte position is known, while using the conflict check to catch a bad decoder immediately.

![The recovered PNG showing the Brain Outside result.](/images/hacktheon-sejong/brain-outside-recovered-flag.png)

## CathedralOfTheLastCandle

**Category:** Misc / interactive math  
**Result:** hacktheon2026{35e9acaa476ef8747fc4cb72fa3f24c5242cc541ed96b8e0ac34c303af257621efcbe26110bb7b051540d840813a26d49c9ad69d2ad17a2709ef56e8c7aed44a1a003bcf5b383b3d}

The service exposes a 5×8 board. Each cell is a value in F3: . is 0, ~ is 1, and * is 2. Every non-altar cell is bonded to one orthogonally adjacent cell. At a non-root position, the two operations are:

~~~text
ring: a' = a + b       b' = a + 2b
hush: a' = 2a + 2b     b' = 2a + b       (mod 3)
~~~

The altar at (4, 7) is a special root: ring decrements it and hush increments it.

The two ordinary operations can be written as matrices over `F3`:

```text
R = [[1, 1], [1, 2]]
H = [[2, 2], [2, 1]] = R⁻¹
```

That inverse relationship is what makes probing safe. I can apply `ring` to learn how a cell changes, then apply `hush` to restore the exact state. Without reversibility, mapping the hidden bonds would consume the puzzle's state rather than just its command budget.

I started by mapping the board. The solver walks it in a snake pattern and records every visible cell, then probes each cell with `ring`. Because `ring` is reversible and changes only the cell and its hidden neighbor, comparing the screens reveals the bond. A second probe settles the ambiguous cases.

The recovered directed bonds form a tree leading to the altar. A greedy “clear leaves first” strategy spends too much of the 300-command budget, so the solver builds a 3×3 transition matrix for each subtree. It answers a simple question: if the parent starts in state `b0`, what is the cheapest way to clear the subtree and return with the parent in state `b1`?

For a child subtree `u`, `DP_u[b0][b1]` stores that minimum cost. The local search state is small: the current value of `u`, the current value of its parent, and a bitmask of processed children. Processing a child is itself a transition supplied by the child's table; `ring` and `hush` are the two local transitions. Dijkstra is convenient because every command has positive cost and back-pointers give the actual command list, not just the number.

Each local state tracks the current node value, its parent value, and which children have already been processed. Dijkstra's algorithm is enough because every transition has positive cost. Back-pointers reconstruct the actual go, ring, and hush commands, and a local simulator validates the sequence before it is sent.

The successful run used 153 commands for mapping, 126 for solving, and one final pray: 280 commands in total.

The 153-command mapping cost is not just movement. It includes the reversible probes used to identify each bond. That is why I would not replace the tree solver with a hand-written “clear leaves” routine: a solution that is correct but spends 301 commands is still a failure.

### Solver / reproduction

The solver maps the board, probes its hidden bonds, then builds and simulates the command sequence. [Download `cathedral_solve.py`](/solvers/hacktheon-sejong-2026/cathedral_solve.py).

## Immutable

**Category:** Pwn  
**Local result:** hacktheon2026{fake_flag} — the placeholder stored in the local challenge bundle, not a claimed remote flag

The challenge description asks how to change an immutable value. The binary already contains the win path: if a stack integer equals 0xdeadbeef, it prints “You win!” and calls system("/bin/sh"). The problem is reaching that comparison without breaking the canary.

The binary is a PIE-enabled, dynamically linked amd64 ELF with Full RELRO, a stack canary, NX, SHSTK, and IBT. Those protections look intimidating, but this solve does not need a return-address overwrite. The binary is also not stripped, so the relevant code path is easy to inspect.

The input is read with:

~~~c
char buf[128];
scanf("%s", buf);

if (immutable_value == 0xdeadbeef) {
    puts("You win!");
    system("/bin/sh");
}
~~~

The disassembly places the input buffer at rbp - 0x90 and the checked integer at rbp - 0x10. Their distance is:

~~~text
(rbp - 0x10) - (rbp - 0x90) = 0x80 = 128
~~~

That gives the overwrite layout:

~~~text
offset 0    .. 127: 128 bytes of filler
offset 128  .. 131: 0xdeadbeef, little-endian as ef be ad de
offset 132:         scanf's terminating NUL
~~~

The canary is at rbp - 0x8. Since the NUL written at offset 132 lands at rbp - 0x0c, it stays four bytes before the canary. We can therefore change the checked integer while leaving the stack-protection value intact.

The little-endian byte order is the only part of the payload that is easy to get backwards: the integer must appear as `ef be ad de`, not as the human-readable `de ad be ef`. The newline after it is also deliberate. `scanf("%s")` appends a NUL after the four-byte value, and the following shell commands are read by the `/bin/sh` opened by the built-in win path.

### Local reproduction

The submitted local proof is enough to reproduce it:

~~~bash
python3 - <<'PY' | ./immutable
import sys

payload = b"A" * 128
payload += (0xdeadbeef).to_bytes(4, "little")
payload += b"\ncat flag\nexit\n"
sys.stdout.buffer.write(payload)
PY
~~~

The expected local output is:

~~~text
Give me a input: You win!
hacktheon2026{fake_flag}
~~~

The [socket solver](/solvers/hacktheon-sejong-2026/immutable_solve.py) sends the same payload to a running instance.

## Plottergeist

**Category:** Forensics / side-channel analysis  
**Result:** hacktheon2026{the_plotter_reveals_its_secret_through_sound}

The challenge gave us a motion pcap and a microphone recording. The packet capture says where the plotter head moved, but not whether the pen was touching the paper during each move.

One UDP payload revealed the custom format:

~~~text
FMT:OP|SQ|DT|AM|BM~
~~~

Motion packets begin with 0xa1, followed by a sequence number, a duration-like field, and two signed 16-bit motor values. Decoding the packets exposes a regular seven-row scanline raster. That recovers the geometry, but not the pixels: the same path can be drawn with the pen down or traversed with the pen up.

The `DT = 24` reset packets are the row separators. I used the motor values to integrate the path, then split it into seven scanlines. This makes the pcap a geometry source rather than a pixel source: it tells us where the head was and how long each move lasted, but it does not say whether the pen made contact.

The WAV is the missing bit. Packet timing aligns with short audio windows. Instead of clustering all windows globally, the solver compares repeated motion classes and uses the stable acoustic difference between pen-down and pen-up moves. It labels each scanline segment, renders candidate rasters, and checks the result against the expected image structure.

That comparison matters because the microphone has its own gain and background noise. A global amplitude threshold would make the result depend on where in the recording the move occurred. Reusing the same motor pattern as its own reference cancels much of that variation and leaves the click/scratch difference caused by contact with the paper.

### Solver / reproduction

[Download `plottergeist_solve.py`](/solvers/hacktheon-sejong-2026/plottergeist_solve.py). It takes the pcap and WAV as inputs and writes candidate images to an output directory.

## Voice Over

**Category:** AI / audio processing  
**Result:** hacktheon2026{b7d30e21e4106a6ca4d451a218f15a97}

The service presents a voice-cloning task. Each /api/challenge response supplies a fresh token and a randomized target sentence. /api/verify checks speaker similarity and text similarity.

Black-box testing separated the two checks. The reference clips scored around 0.95–0.98 for the speaker, but their transcript did not match the current target. Plain TTS produced a perfect text score and a poor speaker score. Concatenating or mixing reference audio and TTS audio improved one side while contaminating the other.

The trick came from the RIFF/WAV container. The solver kept the format chunk from a genuine reference sample, then placed two data chunks in the same container:

~~~text
RIFF / WAVE
  fmt  <- reference sample
  data <- reference speaker audio
  data <- synthesized target sentence
~~~

The observed behavior strongly suggests that the speaker model consumes the first data chunk while the ASR path consumes the second. The evidence was unusually clean: the speaker score stayed at the reference level, the transcript matched the synthesized sentence exactly, and both thresholds passed on the same upload.

The WAV header advertises one format chunk, but RIFF permits more than one `data` chunk. The solver keeps the genuine reference format and appends two payloads. A consumer that stops after the first `data` chunk hears the reference speaker; a consumer that concatenates or selects the later chunk sees the synthesized sentence. The vulnerability is not in the voice model itself. It is the disagreement about which bytes constitute “the audio” inside one container.

### Solver / reproduction

[Download `voice_over_solve.py`](/solvers/hacktheon-sejong-2026/voice_over_solve.py). It defaults to a local service at `127.0.0.1:8000`; pass another base URL with `--base-url` if needed.

## Dark Harbor 2

**Category:** Web / cryptography  
**Result:** hacktheon2026{lighth0use_se4l_cr4ck}

Dark Harbor 2 replaces the first challenge's admin console with a phase-one handoff. Supplying the phase-one deployment secret gives a pipeline_admin JWT and a REVIEW workspace.

The handoff path hard-codes every workspace into the same account:

~~~sql
INSERT INTO workspaces (..., account_id, ...)
VALUES (..., 'phase1-clear', ...)
~~~

The JWT carries the same account_id. GET /api/workspaces therefore lists other teams' handoff workspaces, and GET /api/deploy/:workspaceId/override-result checks only the role, not whether the workspace belongs to the caller.

The exploit reads a victim workspace's cached override_result, extracting a victim deploy token and encrypted secret. It then mints a token for that same workspace, redeems the fresh token with seal to obtain the stable session seal, and redeems the leaked token with sign to obtain the matching signing key. The key derivation in crypto_utils.py produces the AES key used to decrypt the ciphertext.

The cryptographic step is not a brute force:

```python
key = HMAC-SHA256(signing_key, session_seal)[:32]
plaintext = decrypt_with_the_challenge_cipher(key, nonce, encrypted_secret)
```

The hard part is obtaining both inputs from the right workspace. A role check answers “is this caller a pipeline admin?” but not “does this caller own workspace 123?” The shared `account_id`, cross-workspace token endpoint, and unscoped Redis lookup turn that missing tenant check into the key-recovery path.

![The live Dark Harbor 2 solve output from the submitted evidence.](/images/hacktheon-sejong/dark-harbor-2-flag.png)

### Solver / reproduction

[Download `dark_harbor2_solve.py`](/solvers/hacktheon-sejong-2026/dark_harbor2_solve.py). It uses the local challenge URL by default and reads `HMAC_SECRET` from `.env` or the environment.

## Until Executing

**Category:** Reverse Engineering  
**Result:** hacktheon2026{ovajumher0erwk128_i8eecp1hb5enitsj61y5hx05qel7a2z1gb6y8vi4fd4193}

The input is the 64-character flag body. A stripped OCaml native binary runs two verifier processes, and both must accept before the program prints the wrapped flag. The first useful detail is an OCaml runtime detail: 0x81 is the tagged representation of integer 64, so the length check really is an exact 64-byte requirement.

The alphabet is limited to lowercase letters, digits, underscores, and !. Proc B uses two 64-entry tables embedded in the binary. For every candidate character, the solver evaluates a current-table equation and a window-table equation, then advances the verifier state only if both checks pass.

That makes the solve a left-to-right depth-first search over at most 38 characters per position, with strong pruning from the two static tables. The hard reversing work was reconstructing the OCaml tagged values, the 9-bit masking, the S-box/rotation helpers, and the state update. It was not a blind 64-character brute force.

OCaml integers are tagged in the native runtime, so constants seen in the disassembly are not always their mathematical values. Recovering the verifier meant separating the tag/un-tag operations from the actual table lookup and state transition. Once that was done, each candidate character could be rejected immediately by the two table equations instead of waiting for the final 64-byte check.

## Recover it!

**Category:** Reverse Engineering  
**Recovered body:** `22c34e819d2800db605d9fdbc9ba9ab71d6b9175d6b3b016c49cd94624f545c3`

The solver recovers the 64-character body by reversing the XOR byte by byte.

The binary requires exactly 64 input bytes and transforms each byte in place:

~~~c
for (i = 0; i <= 0x3f; ++i)
    s[i] ^= (_BYTE)i + 103;
~~~

It then compares the transformed buffer with a 64-byte table in .data. XOR is its own inverse, so the recovery is direct:

~~~python
for i in range(64):
    original[i] = cmptable[i] ^ ((i + 103) & 0xff)
~~~

The apparent ror8 and rol8 helpers are dead code; the main function never calls them. The solver therefore only needs the table bytes and the inverse XOR loop.

This is a good small reversing habit: trace the call graph before spending time on every helper. The presence of rotation routines in the binary does not make them part of the check. The bytes used by `main` form a simple triangular XOR transform, so inverting them index by index is enough.

![IDA showing the XOR loop and length check.](/images/hacktheon-sejong/recover-it-ida.png)

![The extracted comparison table from the submitted evidence.](/images/hacktheon-sejong/recover-it-cmptable.png)

### Solver / reproduction

[Download `recover_it_solve.py`](/solvers/hacktheon-sejong-2026/recover_it_solve.py).
