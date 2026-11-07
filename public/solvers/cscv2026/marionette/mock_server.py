#!/usr/bin/env python3
"""Explicit local fixture for exercising solve.py's protocol/exploit path.

This is an abstract primitive harness, not a reimplementation of the missing
Marionette service or evidence about the organizer's binary.
"""
import argparse
import os
import re
import socket
import struct
import threading

MASK64 = (1 << 64) - 1
FNV_OFFSET = 0xcbf29ce484223325
FNV_PRIME = 0x100000001B3
G0 = 0xe3a7d1b5924f6c80
G1 = 0x9fed4fa8a9104ce8
MIX_A = 0xff51afd7ed558ccd
MIX_B = 0xc4ceb9fe1a85ec53
MIX_C = 0x9fcefcacc5ea5bfb


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
    state = (G0 ^ G1) ^ nonce
    for _ in range((h2 % 7) + 3 + (h3 & 3) + 2):
        state = xs128(state)
    return mix(mix(state) ^ MIX_C)


def mac_for(seq, prev, payload):
    h = FNV_OFFSET if seq == 1 else prev
    for b in struct.pack('<IQ', seq, prev) + payload:
        h = ((h ^ b) * FNV_PRIME) & MASK64
    return h


def recv_exact(sock, size):
    out = bytearray()
    while len(out) < size:
        part = sock.recv(size - len(out))
        if not part:
            raise EOFError('peer closed during frame')
        out.extend(part)
    return bytes(out)


def decode_pushes(code):
    """Yield ('push', qword) and ('op', opcode) for the exploit's bytecode subset."""
    out = []
    i = 0
    while i < len(code):
        op = code[i]
        i += 1
        if op == 0x01:
            if i + 8 > len(code):
                raise ValueError('truncated PUSH')
            out.append(('push', struct.unpack_from('<Q', code, i)[0]))
            i += 8
        else:
            out.append(('op', op))
    return out


class FixtureVM:
    def __init__(self, flag):
        self.flag = flag.encode() if isinstance(flag, str) else flag
        self.nonce = int.from_bytes(os.urandom(8), 'big')
        self.ctx = 0x555500000000
        self.slots = [self.ctx + 0xfa0, self.ctx + 0x1100, self.ctx + 0x1180, self.ctx + 0x1200]
        self.key = 0x8d73a94126bc50ef
        ba0, ab0 = 0x1122334455667788, 0x76543210fedcba98
        self.memory = {
            self.ctx + 0xba0: ba0,
            self.ctx + 0xab0: ab0,
            self.ctx + 0xbb0: mix(ba0 ^ self.key ^ ab0),
        }
        self.unlocked = False
        self.leaks = 0
        self.capacity_write = False

    def execute_fixture_subset(self, code):
        """Model just the primitive contract exercised by exploit_prints()."""
        ins = decode_pushes(code)
        outputs = []
        pushes = []
        writes = []
        i = 0
        while i < len(ins):
            kind, value = ins[i]
            if kind == 'push':
                pushes.append(value)
                i += 1
                continue

            op = value
            if op == 0x43:  # GETSLOT uses the top stack index
                slot = pushes[-1] if pushes else 0
                slot &= MASK64
                outputs.append(self.slots[slot] if slot < len(self.slots) else 0)
                self.leaks += 1
                pushes.clear()
            elif op == 0x60:  # SHUFFLE: fixture tracks its encoded helper operands
                if len(pushes) >= 3:
                    index, val, mode = pushes[-3:]
                    writes.append((index, val, mode))
                    # In the read helper, the trailing (0,0,0) tuple reads the
                    # address placed by its preceding -2 write.
                    if index == 0 and val == 0 and mode == 0 and len(writes) >= 1:
                        target = writes[-2][1] if len(writes) >= 2 else 0
                        outputs.append(self.memory.get(target, 0))
                    # Recognize the fixture's requested capacity update.
                    if index == 0 and val == ((0x201 << 32) | 2):
                        self.capacity_write = True
                        outputs.append(val)
                pushes.clear()
            elif op == 0x50:  # PRINTI in the supplied bytecode
                # Values collected by preceding primitive dispatches are emitted below.
                pushes.clear()
            elif op == 0x66 and i + 1 < len(ins) and ins[i + 1] == ('op', 0x51):
                args = pushes[-3:] if len(pushes) >= 3 else []
                if self.unlocked and self.capacity_write and len(args) == 3 and args[2] == self.key:
                    return self.flag + b'\n'
                return b'fixture finale rejected\n'
            else:
                # The challenge exploit uses no other VM instructions in this fixture.
                pushes.clear()
            i += 1
        if outputs:
            return b''.join(str(x & MASK64).encode() + b'\n' for x in outputs)
        return b''


def serve_client(conn, addr, flag):
    vm = FixtureVM(flag)
    print(f'[fixture] connected {addr}; nonce={vm.nonce:016x}')
    prev = 0
    expected_seq = 1
    try:
        # ASCII nonce matches the binary's SESSION NONCE %016llx format.
        conn.sendall(f'SESSION NONCE {vm.nonce:016x}\nREADY\n'.encode())
        while True:
            hdr = recv_exact(conn, 15)  # >BIQH is 15 bytes
            typ, seq, supplied_mac, size = struct.unpack('>BIQH', hdr)
            payload = recv_exact(conn, size) if size else b''
            if seq != expected_seq:
                raise ValueError(f'seq {seq}, expected {expected_seq}')
            if mac_for(seq, prev, payload) != supplied_mac:
                raise ValueError(f'MAC mismatch at seq {seq}')
            prev = supplied_mac
            expected_seq += 1

            if typ == 0x50:
                if len(payload) != 8 or struct.unpack('<Q', payload)[0] != stage_key(vm.nonce):
                    raise ValueError('stage token rejected')
                vm.unlocked = True
                conn.sendall(b'#OK\n')
                print('[fixture] authenticated stage unlock')
            elif typ == 1:
                if not vm.unlocked:
                    conn.sendall(b'not ready\n')
                    continue
                if len(payload) < 2:
                    conn.sendall(b'bad program\n')
                    continue
                plen = struct.unpack('>H', payload[:2])[0]
                if plen != len(payload) - 2:
                    conn.sendall(b'bad program\n')
                    continue
                output = vm.execute_fixture_subset(payload[2:])
                conn.sendall(output)
                if b'CSCV2026{' in output:
                    print(f'[fixture] emitted configured local fixture flag: {output.strip().decode(errors="replace")}')
            elif typ == 2:
                conn.sendall(b'POOLINFO fixture\n')
            elif typ == 3:
                break
            else:
                conn.sendall(b'unknown frame\n')
    except (EOFError, ConnectionResetError, BrokenPipeError):
        pass
    except Exception as exc:
        print(f'[fixture] {addr}: {exc}')
    finally:
        conn.close()
        print(f'[fixture] closed {addr}')


def main():
    ap = argparse.ArgumentParser(description='Local exploit-path fixture; not the organizer service')
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--port', type=int, default=9998)
    ap.add_argument('--flag', default='flag.txt')
    args = ap.parse_args()
    try:
        with open(args.flag, 'rb') as f:
            flag = f.read().strip()
    except OSError as exc:
        ap.error(f'cannot read fixture flag file {args.flag!r}: {exc}')
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(5)
    print(f'[fixture] listening on {args.host}:{args.port}; flag source={args.flag}')
    print('[fixture] this only emulates the exploit-facing primitive contract')
    try:
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=serve_client, args=(conn, addr, flag), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        srv.close()


if __name__ == '__main__':
    main()
