#!/usr/bin/env sage
"""
Solver for the HTB crypto challenge "Hidden Secret".

Usage:
    sage hidden_secret_solve.sage output.txt

The expensive first LLL result is cached beside output.txt. Delete the .sobj
cache if you change the challenge instance.
"""

from sage.all import *
from itertools import product
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
except ImportError as exc:
    raise SystemExit(
        "PyCryptodome is missing from this Sage environment. "
        "Install it with: sage -pip install pycryptodome"
    ) from exc
import argparse
import ast
import hashlib
import os
import re
import sys
import time

SAMPLES = 7
ORIGINAL_DEGREE = 39          # chall.py uses j = 0, ..., 39
LIFT_DEGREE = 4
CURVE_DEGREE = LIFT_DEGREE * ORIGINAL_DEGREE   # 156
WEIGHT_COUNT = CURVE_DEGREE + 1                # 157
AUX_PRIME = Integer(2)**61 - 1


def weak_compositions(total, length):
    """All length-tuples of nonnegative integers summing to total."""
    out = []

    def rec(prefix, remaining, slots):
        if slots == 1:
            out.append(tuple(prefix + [remaining]))
            return
        for value in range(remaining + 1):
            rec(prefix + [value], remaining - value, slots - 1)

    rec([], total, length)
    return out


def parse_output(path):
    text = open(path, "r").read()
    match_pub = re.search(r"^pub\s*=\s*(.+)$", text, re.MULTILINE)
    match_enc = re.search(r"encflag\s*=\s*bytes\.fromhex\(['\"]([0-9a-fA-F]+)['\"]\)", text)
    if not match_pub or not match_enc:
        raise ValueError("could not parse pub / encflag from output.txt")

    p, ys = ast.literal_eval(match_pub.group(1))
    if len(ys) != SAMPLES:
        raise ValueError("expected %d public samples, got %d" % (SAMPLES, len(ys)))
    return Integer(p), [Integer(y) for y in ys], bytes.fromhex(match_enc.group(1))


def pure_veronese_int(c, exponents):
    """Unweighted degree-4 Veronese coordinates: product(c_i^e_i)."""
    return [prod(Integer(c[i]) ** e[i] for i in range(len(c))) for e in exponents]


def first_order_vector_int(c0, c1, exponents):
    """
    Coefficient of T in product_i (c0_i + c1_i*T)^e_i.
    These are the first-order lifted coordinates.
    """
    result = []
    for e in exponents:
        value = Integer(0)
        for i, ei in enumerate(e):
            if ei == 0:
                continue
            term = Integer(ei) * Integer(c1[i])
            for j, ej in enumerate(e):
                power = ej - (1 if j == i else 0)
                term *= Integer(c0[j]) ** power
            value += term
        result.append(value)
    return result


def normalize_ternary_projective(c):
    c = tuple(Integer(v) for v in c)
    for v in c:
        if v != 0:
            return c if v > 0 else tuple(-x for x in c)
    raise ValueError("zero vector has no projective normalization")


def lifted_public_vector(ys, p, exponents):
    return vector(ZZ, [prod(pow(int(ys[i]), e[i], int(p)) for i in range(SAMPLES)) % p
                       for e in exponents])


def orthogonal_lattice_basis(b, p):
    """Basis of {u in Z^m : <u,b> == 0 mod p}."""
    m = len(b)
    pivot = next((i for i, value in enumerate(b) if value % p != 0), None)
    if pivot is None:
        raise ValueError("the lifted public vector is zero")
    if pivot != 0:
        raise ValueError("internal error: lifted coordinates must be pivoted before this call")

    inv_b0 = inverse_mod(Integer(b[0]), p)
    lattice = zero_matrix(ZZ, m, m)
    lattice[0, 0] = p
    for i in range(1, m):
        lattice[i, i] = 1
        lattice[i, 0] = (-Integer(b[i]) * inv_b0) % p
    return lattice


def recover_relation_lattice(b, p, relation_count, cache_path=None):
    if cache_path and os.path.exists(cache_path):
        print("[*] loading cached relation lattice:", cache_path)
        saved_p, saved_b0, saved_len, K = load(cache_path)
        if Integer(saved_p) == p and Integer(saved_b0) == Integer(b[0]) and Integer(saved_len) == len(b):
            return matrix(ZZ, K)
        print("[!] cache does not match this instance; recomputing")

    print("[*] building the %d-dimensional modular orthogonal lattice" % len(b))
    L = orthogonal_lattice_basis(b, p)
    print("[*] running fpLLL; this is the expensive stage")
    started = time.time()
    reduced = L.LLL(delta=0.99, algorithm="fpLLL:wrapper")
    print("[+] LLL finished in %.1f seconds" % (time.time() - started))

    rows = sorted(reduced.rows(), key=lambda row: row.dot_product(row))
    if relation_count >= len(rows):
        raise ValueError("invalid relation count")

    before_bits = Integer(rows[relation_count - 1].dot_product(rows[relation_count - 1])).nbits()
    after_bits = Integer(rows[relation_count].dot_product(rows[relation_count])).nbits()
    print("[*] squared-norm bit gap around cutoff: %d -> %d" % (before_bits, after_bits))

    K = matrix(ZZ, rows[:relation_count])
    if K.rank() != relation_count:
        raise RuntimeError("short LLL vectors did not have the expected rank")
    modular_check = K * b
    if any(modular_check[i] % p != 0 for i in range(K.nrows())):
        raise RuntimeError("LLL rows are not modular relations")

    if cache_path:
        save((p, Integer(b[0]), len(b), K), cache_path)
        print("[*] cached relation lattice:", cache_path)
    return K


def batch_zero_columns(M):
    """Indices of zero columns of a Sage matrix."""
    return [j for j in range(M.ncols()) if all(M[i, j] == 0 for i in range(M.nrows()))]


def find_ternary_endpoints(K, exponents):
    """Find ternary c for which nu_4(c) belongs to the recovered curve span."""
    candidates = []
    columns = []
    for raw in product((-1, 0, 1), repeat=SAMPLES):
        if not any(raw):
            continue
        first = next(v for v in raw if v != 0)
        if first < 0:                 # c and -c have the same fourth Veronese point
            continue
        c = tuple(Integer(v) for v in raw)
        candidates.append(c)
        columns.append(pure_veronese_int(c, exponents))

    Fq = GF(AUX_PRIME)
    Kq = matrix(Fq, K)
    V = matrix(Fq, columns).transpose()
    possible = batch_zero_columns(Kq * V)

    endpoints = []
    zero_exact = zero_vector(ZZ, K.nrows())
    for j in possible:
        c = candidates[j]
        v = vector(ZZ, columns[j])
        if K * v == zero_exact:
            endpoints.append(c)

    endpoints = sorted(set(endpoints))
    print("[+] ternary endpoint candidates:", endpoints)
    if len(endpoints) < 2:
        raise RuntimeError(
            "fewer than two ternary endpoints were recovered; the LLL cutoff is probably wrong"
        )
    return endpoints


def find_first_order_candidates(K, c0, exponents):
    """All ternary c1 whose first lifted coefficient lies in the curve span."""
    ternary = [tuple(Integer(v) for v in raw) for raw in product((-1, 0, 1), repeat=SAMPLES)]
    columns = [first_order_vector_int(c0, c1, exponents) for c1 in ternary]

    Fq = GF(AUX_PRIME)
    possible = batch_zero_columns(matrix(Fq, K) * matrix(Fq, columns).transpose())
    zero_exact = zero_vector(ZZ, K.nrows())

    result = []
    for j in possible:
        q1 = vector(ZZ, columns[j])
        if K * q1 == zero_exact:
            result.append((ternary[j], q1))
    print("[*] %d ternary first-order candidates at %s" % (len(result), tuple(c0)))
    return result


def derivative_matrix(F, point, exponents, variable_indices):
    rows = []
    for e in exponents:
        row = []
        for i in variable_indices:
            if e[i] == 0:
                row.append(F(0))
                continue
            value = F(e[i])
            for j, ej in enumerate(e):
                power = ej - (1 if j == i else 0)
                value *= point[j] ** power
            row.append(value)
        rows.append(row)
    return matrix(F, rows)


def local_lifted_jets(Kp, exponents4, endpoint, max_order):
    """
    Compute nu_4(z(t)) through t^max_order on the curve near endpoint.

    A nonzero tangent coordinate is fixed to equal t. At each order the same
    Jacobian solves the next coefficient, since the equations are quartic.
    """
    F = Kp.base_ring()
    endpoint = normalize_ternary_projective(endpoint)
    chart = next(i for i, value in enumerate(endpoint) if value != 0)
    scale = F(endpoint[chart]) ** -1
    point = [F(v) * scale for v in endpoint]
    variables = [i for i in range(SAMPLES) if i != chart]

    D = derivative_matrix(F, point, exponents4, variables)
    J = Kp * D
    tangent_kernel = J.right_kernel()
    if tangent_kernel.dimension() != 1:
        raise RuntimeError("endpoint is not a smooth curve point (tangent dimension %d)" % tangent_kernel.dimension())
    tangent = tangent_kernel.basis()[0]
    gauge_index = next(i for i, value in enumerate(tangent) if value != 0)

    gauge_row = matrix(F, 1, len(variables), [1 if i == gauge_index else 0
                                               for i in range(len(variables))])
    augmented = J.stack(gauge_row)
    independent_rows = list(augmented.transpose().pivots())
    if len(independent_rows) != len(variables):
        raise RuntimeError("could not construct a nonsingular local Jacobian")
    square = augmented.matrix_from_rows(independent_rows)
    square_inverse = square.inverse()

    exponents_by_degree = {d: weak_compositions(d, SAMPLES) for d in range(LIFT_DEGREE + 1)}
    zero_exp = tuple([0] * SAMPLES)
    all_exponents = []
    for d in range(LIFT_DEGREE + 1):
        all_exponents.extend(exponents_by_degree[d])

    z = [[F(0) for _ in range(max_order + 1)] for _ in range(SAMPLES)]
    for i in range(SAMPLES):
        z[i][0] = point[i]

    series = {e: [F(0) for _ in range(max_order + 1)] for e in all_exponents}
    series[zero_exp][0] = F(1)

    parent = {}
    for degree in range(1, LIFT_DEGREE + 1):
        for e in exponents_by_degree[degree]:
            i = next(i for i, value in enumerate(e) if value != 0)
            lower = list(e)
            lower[i] -= 1
            parent[e] = (tuple(lower), i)

    def recompute_coefficient(order):
        for degree in range(1, LIFT_DEGREE + 1):
            for e in exponents_by_degree[degree]:
                lower, i = parent[e]
                value = F(0)
                for a in range(order + 1):
                    value += series[lower][a] * z[i][order - a]
                series[e][order] = value

    recompute_coefficient(0)
    jets = [vector(F, [series[e][0] for e in exponents4])]

    print("[*] expanding at infinity candidate %s to order %d" % (tuple(endpoint), max_order))
    for order in range(1, max_order + 1):
        # The new z_i[order] are currently zero, so this is the nonlinear residual.
        recompute_coefficient(order)
        base_h = vector(F, [series[e][order] for e in exponents4])
        residual = Kp * base_h

        gauge_value = F(1) if order == 1 else F(0)
        rhs_full = vector(F, list(-residual) + [gauge_value])
        rhs_small = vector(F, [rhs_full[i] for i in independent_rows])
        coefficient = square_inverse * rhs_small
        if augmented * coefficient != rhs_full:
            raise RuntimeError("inconsistent local expansion at order %d" % order)

        for position, coordinate in enumerate(variables):
            z[coordinate][order] = coefficient[position]

        recompute_coefficient(order)
        h_order = vector(F, [series[e][order] for e in exponents4])
        if Kp * h_order != zero_vector(F, Kp.nrows()):
            raise RuntimeError("local curve equation failed at order %d" % order)
        jets.append(h_order)

        if order % 20 == 0 or order == max_order:
            print("    jet %d/%d" % (order, max_order))

    H = matrix(F, jets).transpose()
    if H.rank() != max_order + 1:
        raise RuntimeError("lifted jets do not span the expected rational normal curve")
    return H, jets


def osculating_functionals(Kp, exponents, infinity_endpoint):
    """
    Return two functionals on the lifted curve:
      ell_A has local leading term t^(N-1) at infinity,
      ell_B has local leading term t^N at infinity.
    """
    F = Kp.base_ring()
    H, jets = local_lifted_jets(Kp, exponents, infinity_endpoint, CURVE_DEGREE)

    pivot_rows = list(H.transpose().pivots())
    if len(pivot_rows) != WEIGHT_COUNT:
        raise RuntimeError("could not select independent lifted coordinates")
    square = H.matrix_from_rows(pivot_rows)

    targets = zero_matrix(F, WEIGHT_COUNT, 2)
    targets[CURVE_DEGREE - 1, 0] = 1
    targets[CURVE_DEGREE, 1] = 1
    supported = square.transpose().solve_right(targets)

    ell_a = zero_vector(F, len(exponents))
    ell_b = zero_vector(F, len(exponents))
    for position, row in enumerate(pivot_rows):
        ell_a[row] = supported[position, 0]
        ell_b[row] = supported[position, 1]

    for j in range(CURVE_DEGREE + 1):
        expected_a = F(1) if j == CURVE_DEGREE - 1 else F(0)
        expected_b = F(1) if j == CURVE_DEGREE else F(0)
        if ell_a.dot_product(jets[j]) != expected_a or ell_b.dot_product(jets[j]) != expected_b:
            raise RuntimeError("dual osculating functional verification failed")
    return ell_a, ell_b


def decrypt_with_x(x, encrypted):
    x = Integer(x)
    key = hashlib.sha256(str(x).encode()).digest()
    plaintext_padded = AES.new(key, AES.MODE_ECB).decrypt(encrypted)
    try:
        plaintext = unpad(plaintext_padded, 16)
    except ValueError:
        return None
    return plaintext


def plausible_flag(data):
    if data is None or len(data) == 0:
        return False
    if not all(byte in (9, 10, 13) or 32 <= byte < 127 for byte in data):
        return False
    return (b"{" in data and data.rstrip().endswith(b"}")) or data.startswith(b"HTB")


def solve(output_path, cache_path=None, use_cache=True):
    p, ys, encrypted = parse_output(output_path)
    print("[*] modulus bits:", p.nbits())
    print("[*] ciphertext bytes:", len(encrypted))

    exponents = weak_compositions(LIFT_DEGREE, SAMPLES)
    if len(exponents) != binomial(SAMPLES + LIFT_DEGREE - 1, LIFT_DEGREE):
        raise RuntimeError("bad monomial enumeration")

    b = lifted_public_vector(ys, p, exponents)
    pivot = next(i for i, value in enumerate(b) if value % p != 0)
    if pivot != 0:
        exponents[0], exponents[pivot] = exponents[pivot], exponents[0]
        values = list(b)
        values[0], values[pivot] = values[pivot], values[0]
        b = vector(ZZ, values)

    relation_count = len(exponents) - WEIGHT_COUNT
    print("[*] quartic monomials: %d; hidden weights: %d; relations: %d" %
          (len(exponents), WEIGHT_COUNT, relation_count))

    if cache_path is None:
        cache_path = output_path + ".hidden_secret_kernel.sobj"
    K = recover_relation_lattice(b, p, relation_count, cache_path if use_cache else None)

    endpoints = find_ternary_endpoints(K, exponents)
    first_order = {c0: find_first_order_candidates(K, c0, exponents) for c0 in endpoints}

    # p is generated by chall.py with Crypto.Util.number.getPrime.
    # Avoid Sage spending a long time proving primality for this 8192-bit modulus.
    Fp = GF(p, proof=False)
    Kp = matrix(Fp, K)
    h_public = vector(Fp, [Fp(value) for value in b])
    h_endpoint = {c: vector(Fp, pure_veronese_int(c, exponents)) for c in endpoints}

    tried_x = set()
    possible_plaintexts = []
    osculating_cache = {}

    for infinity_endpoint in endpoints:
        print("[*] constructing degree-one coordinate with infinity at", infinity_endpoint)
        if infinity_endpoint not in osculating_cache:
            osculating_cache[infinity_endpoint] = osculating_functionals(
                Kp, exponents, infinity_endpoint
            )
        ell_a, ell_b = osculating_cache[infinity_endpoint]

        for zero_endpoint in endpoints:
            if zero_endpoint == infinity_endpoint:
                continue

            h0 = h_endpoint[zero_endpoint]
            denominator_at_zero = ell_b.dot_product(h0)
            if denominator_at_zero == 0:
                continue

            # Unique section in span(ell_a, ell_b) that also vanishes at zero_endpoint.
            ell_one = ell_a - (ell_a.dot_product(h0) / denominator_at_zero) * ell_b
            if ell_one.dot_product(h0) != 0:
                raise RuntimeError("failed to impose the zero endpoint")

            public_denominator = ell_b.dot_product(h_public)
            if public_denominator == 0:
                continue
            r_public = ell_one.dot_product(h_public) / public_denominator

            for c1, q1_integer in first_order[zero_endpoint]:
                q1 = vector(Fp, q1_integer)
                linear_coefficient = ell_one.dot_product(q1)
                if linear_coefficient == 0:
                    continue

                # ell_b(h(x)) is constant and ell_one(h(x)) is B*x, so r = (B/A)*x.
                scale = linear_coefficient / denominator_at_zero
                x_field = r_public / scale
                x_candidate = Integer(x_field)
                if x_candidate in tried_x:
                    continue
                tried_x.add(x_candidate)

                plaintext = decrypt_with_x(x_candidate, encrypted)
                if plaintext is not None:
                    possible_plaintexts.append((x_candidate, plaintext, zero_endpoint,
                                                infinity_endpoint, c1))
                if plausible_flag(plaintext):
                    print("[+] recovered x =", x_candidate)
                    print("[+] flag =", plaintext.decode(errors="replace"))
                    open("recovered_flag.txt", "wb").write(plaintext + b"\n")
                    open("recovered_x.txt", "w").write(str(x_candidate) + "\n")
                    return x_candidate, plaintext

    print("[-] no flag-looking plaintext was found")
    if possible_plaintexts:
        print("[*] PKCS#7-valid candidates:")
        for x_candidate, plaintext, zero_endpoint, infinity_endpoint, c1 in possible_plaintexts:
            print("    x =", x_candidate)
            print("    endpoints =", zero_endpoint, infinity_endpoint, "c1 =", c1)
            print("    plaintext =", repr(plaintext))
    raise RuntimeError("solver exhausted all endpoint/orientation/sign candidates")


def main():
    parser = argparse.ArgumentParser(description="Solve the Hidden Secret crypto challenge")
    parser.add_argument("output", nargs="?", default="output.txt", help="challenge output.txt")
    parser.add_argument("--cache", default=None, help="path for the cached LLL relation lattice")
    parser.add_argument("--no-cache", action="store_true", help="do not load or save the LLL cache")
    args = parser.parse_args()

    if not os.path.exists(args.output):
        parser.error("file not found: %s" % args.output)
    solve(args.output, args.cache, not args.no_cache)


if __name__ == "__main__":
    main()
