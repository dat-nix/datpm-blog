#!/usr/bin/env python3
"""Offline solver for HTB Crypto / The Ashen Field.

Usage:
    python3 ashen_field.py output.txt
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import itertools
import re
from pathlib import Path

VAR_RE = re.compile(r"^x([0-9]+)(?:\^[0-9]+)?$")


def aes_ecb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    try:
        from Crypto.Cipher import AES  # type: ignore
        from Crypto.Util.Padding import unpad  # type: ignore

        return unpad(AES.new(key, AES.MODE_ECB).decrypt(ciphertext), 16)
    except ImportError:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.padding import PKCS7

        dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
        padded = dec.update(ciphertext) + dec.finalize()
        unpadder = PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()


def parse_polynomial(poly: str, n: int) -> tuple[int, int]:
    """Return (coefficient bitset, affine constant) over GF(2).

    In the Boolean quotient x^2=x, so x^2 and x^4 both reduce to x.
    """
    coeffs = 0
    constant = 0
    poly = poly.strip()
    if poly == "0":
        return coeffs, constant

    for term in poly.split(" + "):
        term = term.strip()
        if term == "1":
            constant ^= 1
            continue
        match = VAR_RE.fullmatch(term)
        if not match:
            raise ValueError(f"unsupported polynomial term: {term!r}")
        index = int(match.group(1)) - 1
        if not 0 <= index < n:
            raise ValueError(f"variable index out of range: x{index + 1}")
        coeffs ^= 1 << index
    return coeffs, constant


def solve_affine(rows: list[int], rhs: list[int], n: int) -> tuple[int, list[int], int]:
    """Solve A*x=b over GF(2), returning one solution and nullspace basis."""
    aug = [rows[i] | ((rhs[i] & 1) << n) for i in range(len(rows))]
    pivot_row_for_col = [-1] * n
    rank = 0

    for col in range(n):
        selected = next((r for r in range(rank, len(aug)) if (aug[r] >> col) & 1), None)
        if selected is None:
            continue
        aug[rank], aug[selected] = aug[selected], aug[rank]
        pivot_row_for_col[col] = rank
        for r in range(len(aug)):
            if r != rank and ((aug[r] >> col) & 1):
                aug[r] ^= aug[rank]
        rank += 1

    coeff_mask = (1 << n) - 1
    for row in aug:
        if (row & coeff_mask) == 0 and ((row >> n) & 1):
            raise ValueError("linear system is inconsistent")

    particular = 0
    for col, r in enumerate(pivot_row_for_col):
        if r != -1 and ((aug[r] >> n) & 1):
            particular |= 1 << col

    free_cols = [c for c, r in enumerate(pivot_row_for_col) if r == -1]
    basis: list[int] = []
    for free_col in free_cols:
        vector = 1 << free_col
        for pivot_col, r in enumerate(pivot_row_for_col):
            if r != -1 and ((aug[r] >> free_col) & 1):
                vector |= 1 << pivot_col
        basis.append(vector)

    return particular, basis, rank


def parse_output(path: Path) -> tuple[list[str], list[int], bytes]:
    lines = path.read_text().splitlines()
    if len(lines) < 3:
        raise ValueError("output file must contain three lines")

    pk_line = lines[0].strip()
    if not (pk_line.startswith("(") and pk_line.endswith(")")):
        raise ValueError("unexpected public-key tuple format")
    polynomials = pk_line[1:-1].split(", ")
    encrypted_key = list(map(int, ast.literal_eval(lines[1].strip())))
    ciphertext = bytes.fromhex(lines[2].strip())
    if len(polynomials) != len(encrypted_key):
        raise ValueError("public-key and encrypted-vector dimensions differ")
    return polynomials, encrypted_key, ciphertext


def solve(path: Path) -> list[tuple[int, bytes]]:
    polynomials, encrypted_key, ciphertext = parse_output(path)
    n = len(polynomials)

    rows: list[int] = []
    rhs: list[int] = []
    for poly, value in zip(polynomials, encrypted_key):
        coeffs, constant = parse_polynomial(poly, n)
        rows.append(coeffs)
        rhs.append((value & 1) ^ constant)

    particular, basis, rank = solve_affine(rows, rhs, n)
    print(f"[+] dimension: {n}, rank: {rank}, free variables: {len(basis)}")

    valid: list[tuple[int, bytes]] = []
    for selector in itertools.product((0, 1), repeat=len(basis)):
        bits = particular
        for enabled, vector in zip(selector, basis):
            if enabled:
                bits ^= vector

        # Sage's Integer.bits() is little-endian and N=KEY.nbits(), so bit i
        # of the solved vector is directly bit i of the integer.
        key_integer = bits
        if key_integer.bit_length() != n:
            continue
        aes_key = hashlib.sha256(str(key_integer).encode()).digest()
        try:
            plaintext = aes_ecb_decrypt(aes_key, ciphertext)
        except ValueError:
            continue
        valid.append((key_integer, plaintext))

    if not valid:
        raise RuntimeError("no candidate produced valid PKCS#7 plaintext")

    for key_integer, plaintext in valid:
        print(f"[+] KEY integer: {key_integer}")
        print(f"[+] AES key: {hashlib.sha256(str(key_integer).encode()).hexdigest()}")
        print(f"[+] plaintext: {plaintext.decode(errors='replace')}")
    return valid


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path, help="challenge output.txt")
    args = parser.parse_args()
    solve(args.output)


if __name__ == "__main__":
    main()
