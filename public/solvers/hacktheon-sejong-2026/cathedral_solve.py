#!/usr/bin/env python3
import argparse
import heapq
import re
import socket
import sys
import time

HOST = "127.0.0.1"
PORT = 9000
H = 5
W = 8
ROOT = (H - 1, W - 1)
INF = 10**9

ANSI_RE = re.compile(rb"\x1b\[[0-9;]*[A-Za-z]")
POS_RE = re.compile(r"Pos:\((\d+),(\d+)\)\s+Budget:\s*(\d+)")
CELL_RE = re.compile(r"\[[.~*]\]|[.~*?]")

VAL = {".": 0, "~": 1, "*": 2}
SYM = {0: ".", 1: "~", 2: "*"}


def clean(data: bytes) -> str:
    return ANSI_RE.sub(b"", data).decode("utf-8", "replace")


def mod3(x: int) -> int:
    return x % 3


def orth_neighbors(pos):
    r, c = pos
    out = []
    if r > 0:
        out.append((r - 1, c))
    if r + 1 < H:
        out.append((r + 1, c))
    if c > 0:
        out.append((r, c - 1))
    if c + 1 < W:
        out.append((r, c + 1))
    return out


def move_cmd(src, dst):
    sr, sc = src
    dr, dc = dst
    if sr + 1 == dr and sc == dc:
        return "go s"
    if sr - 1 == dr and sc == dc:
        return "go n"
    if sr == dr and sc + 1 == dc:
        return "go e"
    if sr == dr and sc - 1 == dc:
        return "go w"
    raise ValueError(f"non-adjacent move: {src} -> {dst}")


def route_commands(src, dst):
    sr, sc = src
    dr, dc = dst
    cmds = []
    while sr < dr:
        cmds.append("go s")
        sr += 1
    while sr > dr:
        cmds.append("go n")
        sr -= 1
    while sc < dc:
        cmds.append("go e")
        sc += 1
    while sc > dc:
        cmds.append("go w")
        sc -= 1
    return cmds


def snake_positions():
    order = []
    for rr in range(H):
        cols = range(W) if rr % 2 == 0 else range(W - 1, -1, -1)
        for cc in cols:
            order.append((rr, cc))
    return order


SNAKE_ORDER = snake_positions()


class Client:
    def __init__(self):
        self.sock = socket.create_connection((HOST, PORT), timeout=30)
        self.buf = b""
        self.last = ""

    def close(self):
        self.sock.close()

    def recv_prompt(self):
        while b"> " not in self.buf:
            chunk = self.sock.recv(65536)
            if not chunk:
                break
            self.buf += chunk
        data, sep, rest = self.buf.partition(b"> ")
        if sep:
            data += sep
        self.buf = rest
        self.last = clean(data)
        return self.last

    def cmd(self, command: str):
        self.sock.sendall(command.encode() + b"\n")
        return self.recv_prompt()


def parse_screen(screen: str):
    pos_m = POS_RE.search(screen)
    if not pos_m:
        raise ValueError("could not parse position")
    pos = (int(pos_m.group(1)), int(pos_m.group(2)))
    budget = int(pos_m.group(3))

    rows = []
    for line in screen.splitlines():
        toks = CELL_RE.findall(line)
        if len(toks) == W:
            row = []
            for tok in toks:
                row.append(tok[1] if tok.startswith("[") else tok)
            rows.append(row)
    if len(rows) != H:
        raise ValueError(f"could not parse grid, got {len(rows)} rows")
    return pos, budget, rows


def merge_known(known, rows):
    for r in range(H):
        for c in range(W):
            if rows[r][c] != "?":
                known[r][c] = VAL[rows[r][c]]


def ring_pair(a, b):
    return mod3(a + b), mod3(a + 2 * b)


def hush_pair(a, b):
    return mod3(2 * a + 2 * b), mod3(2 * a + b)


def infer_bond_after_first_ring(pos, before, after1):
    r, c = pos
    a = VAL[before[r][c]]
    a1 = VAL[after1[r][c]]
    b = mod3(a1 - a)
    nbrs = [n for n in orth_neighbors(pos) if before[n[0]][n[1]] != "?"]
    candidates = [n for n in nbrs if VAL[before[n[0]][n[1]]] == b]
    changed = [n for n in candidates if after1[n[0]][n[1]] != before[n[0]][n[1]]]
    if len(changed) == 1:
        return changed[0]
    if len(candidates) == 1:
        return candidates[0]
    return None


def infer_bond_after_second_ring(pos, before, after2):
    r, c = pos
    a = VAL[before[r][c]]
    a2 = VAL[after2[r][c]]
    if a2 != mod3(2 * a):
        return None
    nbrs = [n for n in orth_neighbors(pos) if before[n[0]][n[1]] != "?"]
    changed = [n for n in nbrs if after2[n[0]][n[1]] != before[n[0]][n[1]]]
    if len(changed) == 1:
        return changed[0]
    return None


def probe_bond(client: Client):
    pos, _, before = parse_screen(client.last)

    first = client.cmd("ring")
    _, _, after1 = parse_screen(first)
    bond = infer_bond_after_first_ring(pos, before, after1)
    if bond is not None:
        client.cmd("hush")
        return bond

    second = client.cmd("ring")
    _, _, after2 = parse_screen(second)
    bond = infer_bond_after_second_ring(pos, before, after2)
    client.cmd("hush")
    client.cmd("hush")
    if bond is not None:
        return bond
    raise ValueError(f"ambiguous bond at {pos}")


def map_session(client: Client):
    client.recv_prompt()
    pos, budget, rows = parse_screen(client.last)
    known = [[None] * W for _ in range(H)]
    parent = {}
    merge_known(known, rows)

    cur = pos
    for target in SNAKE_ORDER:
        for command in route_commands(cur, target):
            pos, budget, rows = parse_screen(client.cmd(command))
            merge_known(known, rows)
            cur = pos

        if target == ROOT:
            continue

        parent[target] = probe_bond(client)
        pos, budget, rows = parse_screen(client.last)
        merge_known(known, rows)
        cur = pos

    if any(known[r][c] is None for r in range(H) for c in range(W)):
        raise ValueError("failed to reveal full board")
    return known, parent, budget


class TreeSolver:
    def __init__(self, board, parent):
        self.board = board
        self.parent = parent
        self.children = {(r, c): [] for r in range(H) for c in range(W)}
        for child, par in parent.items():
            self.children[par].append(child)
        self.memo_cost = {}
        self.memo_prev = {}

    def init_state(self, node):
        return self.board[node[0]][node[1]]

    def solve(self, node):
        if node in self.memo_cost:
            return self.memo_cost[node]

        kids = self.children[node]
        kid_costs = [self.solve(kid) for kid in kids]

        if node == ROOT:
            size = 1 << len(kids)
            dist = [[INF] * 3 for _ in range(size)]
            prev = [[None] * 3 for _ in range(size)]
            a0 = self.init_state(node)
            dist[0][a0] = 0
            heap = [(0, 0, a0)]

            while heap:
                cur_d, mask, a = heapq.heappop(heap)
                if cur_d != dist[mask][a]:
                    continue

                for i, kid in enumerate(kids):
                    if mask >> i & 1:
                        continue
                    M = kid_costs[i]
                    for a2 in range(3):
                        cost = M[a][a2]
                        if cost >= INF:
                            continue
                        new_mask = mask | (1 << i)
                        new_d = cur_d + cost
                        if new_d < dist[new_mask][a2]:
                            dist[new_mask][a2] = new_d
                            prev[new_mask][a2] = (mask, a, ("child", i, a, a2))
                            heapq.heappush(heap, (new_d, new_mask, a2))

                for name, a2 in (("ring", mod3(a - 1)), ("hush", mod3(a + 1))):
                    new_d = cur_d + 1
                    if new_d < dist[mask][a2]:
                        dist[mask][a2] = new_d
                        prev[mask][a2] = (mask, a, (name,))
                        heapq.heappush(heap, (new_d, mask, a2))

            self.memo_cost[node] = dist[(1 << len(kids)) - 1]
            self.memo_prev[node] = prev
            return self.memo_cost[node]

        size = 1 << len(kids)
        out = [[INF] * 3 for _ in range(3)]
        prev_out = [[None] * 3 for _ in range(3)]

        for b0 in range(3):
            dist = [[[INF] * 3 for _ in range(3)] for _ in range(size)]
            prev = [[[None] * 3 for _ in range(3)] for _ in range(size)]
            a0 = self.init_state(node)
            dist[0][a0][b0] = 0
            heap = [(0, 0, a0, b0)]

            while heap:
                cur_d, mask, a, b = heapq.heappop(heap)
                if cur_d != dist[mask][a][b]:
                    continue

                for i, kid in enumerate(kids):
                    if mask >> i & 1:
                        continue
                    M = kid_costs[i]
                    for a2 in range(3):
                        cost = M[a][a2]
                        if cost >= INF:
                            continue
                        new_mask = mask | (1 << i)
                        new_d = cur_d + cost
                        if new_d < dist[new_mask][a2][b]:
                            dist[new_mask][a2][b] = new_d
                            prev[new_mask][a2][b] = (mask, a, b, ("child", i, a, a2))
                            heapq.heappush(heap, (new_d, new_mask, a2, b))

                ar, br = ring_pair(a, b)
                new_d = cur_d + 1
                if new_d < dist[mask][ar][br]:
                    dist[mask][ar][br] = new_d
                    prev[mask][ar][br] = (mask, a, b, ("ring",))
                    heapq.heappush(heap, (new_d, mask, ar, br))

                ah, bh = hush_pair(a, b)
                if new_d < dist[mask][ah][bh]:
                    dist[mask][ah][bh] = new_d
                    prev[mask][ah][bh] = (mask, a, b, ("hush",))
                    heapq.heappush(heap, (new_d, mask, ah, bh))

            full = (1 << len(kids)) - 1
            for b1 in range(3):
                if dist[full][0][b1] < INF:
                    out[b0][b1] = dist[full][0][b1] + 2
                    prev_out[b0][b1] = prev

        self.memo_cost[node] = out
        self.memo_prev[node] = prev_out
        return out

    def emit_root(self, final_state=0):
        prev = self.memo_prev[ROOT]
        kids = self.children[ROOT]
        state = ((1 << len(kids)) - 1, final_state)
        seq = []

        while True:
            entry = prev[state[0]][state[1]]
            if entry is None:
                break
            prev_mask, prev_a, info = entry
            if info[0] == "child":
                _, i, a_in, a_out = info
                seq.append(("child", kids[i], a_in, a_out))
                state = (prev_mask, prev_a)
            else:
                seq.append((info[0],))
                state = (prev_mask, prev_a)

        seq.reverse()
        cmds = []
        for step in seq:
            if step[0] == "child":
                _, kid, a_in, a_out = step
                cmds.extend(self.emit_node(kid, a_in, a_out))
            else:
                cmds.append(step[0])
        return cmds

    def emit_node(self, node, b_in, b_out):
        kids = self.children[node]
        prev = self.memo_prev[node][b_in][b_out]
        state = ((1 << len(kids)) - 1, 0, b_out)
        seq = []

        while True:
            entry = prev[state[0]][state[1]][state[2]]
            if entry is None:
                break
            prev_mask, prev_a, prev_b, info = entry
            if info[0] == "child":
                _, i, a_in, a_out = info
                seq.append(("child", kids[i], a_in, a_out))
                state = (prev_mask, prev_a, prev_b)
            else:
                seq.append((info[0],))
                state = (prev_mask, prev_a, prev_b)

        seq.reverse()
        cmds = [move_cmd(self.parent[node], node)]
        for step in seq:
            if step[0] == "child":
                _, kid, a_in, a_out = step
                cmds.extend(self.emit_node(kid, a_in, a_out))
            else:
                cmds.append(step[0])
        cmds.append(move_cmd(node, self.parent[node]))
        return cmds


def simulate(board, parent, commands):
    state = {(r, c): board[r][c] for r in range(H) for c in range(W)}
    pos = ROOT

    for cmd in commands:
        if cmd.startswith("go "):
            step = cmd.split()[1]
            r, c = pos
            if step == "n":
                pos = (r - 1, c)
            elif step == "s":
                pos = (r + 1, c)
            elif step == "e":
                pos = (r, c + 1)
            elif step == "w":
                pos = (r, c - 1)
            else:
                raise ValueError(f"bad move: {cmd}")
            continue

        if pos == ROOT:
            if cmd == "ring":
                state[pos] = mod3(state[pos] - 1)
            elif cmd == "hush":
                state[pos] = mod3(state[pos] + 1)
            else:
                raise ValueError(f"bad action: {cmd}")
            continue

        if pos not in parent:
            raise ValueError(f"missing parent for {pos}")
        p = parent[pos]
        a = state[pos]
        b = state[p]
        if cmd == "ring":
            state[pos], state[p] = ring_pair(a, b)
        elif cmd == "hush":
            state[pos], state[p] = hush_pair(a, b)
        else:
            raise ValueError(f"bad action: {cmd}")

    ok = all(state[(r, c)] == 0 for r in range(H) for c in range(W))
    return ok, pos


def attempt_once(attempt_no: int):
    client = Client()
    try:
        board, parent, budget = map_session(client)
        solver = TreeSolver(board, parent)
        root_costs = solver.solve(ROOT)
        solve_cost = root_costs[0]

        print(
            f"[attempt {attempt_no}] budget_after_map={budget} solve_cost={solve_cost}",
            file=sys.stderr,
        )

        if solve_cost >= INF or budget < solve_cost + 1:
            return None

        commands = solver.emit_root(0)
        if len(commands) != solve_cost:
            raise ValueError("reconstruction cost mismatch")

        ok, end_pos = simulate(board, parent, commands)
        if not ok or end_pos != ROOT:
            raise ValueError("simulation failed")

        for command in commands:
            client.cmd(command)
        result = client.cmd("pray")
        return result
    finally:
        client.close()


def main():
    global HOST, PORT
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("attempts", nargs="?", type=int, default=20)
    args = parser.parse_args()
    HOST, PORT = args.host, args.port
    attempts = args.attempts

    for attempt in range(1, attempts + 1):
        try:
            result = attempt_once(attempt)
        except Exception as exc:
            print(f"[attempt {attempt}] error: {exc}", file=sys.stderr)
            time.sleep(0.2)
            continue

        if result is None:
            time.sleep(0.2)
            continue

        print(result)
        return

    raise SystemExit("no successful solve within attempt limit")


if __name__ == "__main__":
    main()
