#!/usr/bin/env python3
"""Exhaustive small-component checks; independent of the Rust ANF evaluator.

Reads public constants only. No user keys or data. JSON is reproducible.
"""
import json
import pathlib
import re


ROOT = pathlib.Path(__file__).resolve().parents[2]


def constants():
    source = (ROOT / "impl/n2q-c-ref/src/consts.rs").read_text()
    def body(name):
        return re.search(r"pub const " + name + r"[^=]*=\s*\[(.*?)\];", source, re.S).group(1)
    sbox = [int(x, 16) for x in re.findall(r"0x[0-9a-f]+", body("SBOX"))]
    rc = [int(x, 16) for x in re.findall(r"0x[0-9a-f]+", body("RC"))]
    rots = {w: [tuple(map(int, p)) for p in re.findall(r"\((\d+),\s*(\d+)\)", body(n))]
            for w, n in [(64, "ROTS_320"), (128, "ROTS_640")]}
    assert len(sbox) == 32 and sorted(sbox) == list(range(32))
    assert len(rc) == len(set(rc)) == 16
    return sbox, rc, rots


def parity(x):
    return bin(x).count("1") & 1


def weight(x):
    return bin(x).count("1")


def sbox_metrics(sbox):
    inv = [sbox.index(x) for x in range(32)]
    ddt = [[sum(sbox[x] ^ sbox[x ^ a] == b for x in range(32))
            for b in range(32)] for a in range(32)]
    lat = [[sum(1 if parity(a & x) == parity(b & sbox[x]) else -1
                for x in range(32)) for b in range(32)] for a in range(32)]
    bct = [[sum(inv[sbox[x] ^ b] ^ inv[sbox[x ^ a] ^ b] == a
                for x in range(32)) for b in range(32)] for a in range(32)]
    degrees = []
    for mask in range(1, 32):
        anf = [parity(mask & sbox[x]) for x in range(32)]
        for bit in range(5):
            for x in range(32):
                if x & (1 << bit):
                    anf[x] ^= anf[x ^ (1 << bit)]
        degrees.append(max(weight(x) for x in range(32) if anf[x]))
    differential = max(max(row) for row in ddt[1:])
    walsh = max(abs(lat[a][b]) for a in range(1, 32) for b in range(1, 32))
    return dict(ddt=ddt, walsh=lat, bct=bct, differential_uniformity=differential,
                max_abs_walsh=walsh, max_abs_correlation=walsh / 32,
                nonlinearity=16 - walsh // 2,
                boomerang_uniformity=max(bct[a][b] for a in range(1, 32) for b in range(1, 32)),
                component_degrees=degrees,
                fixed_points=[x for x in range(32) if sbox[x] == x],
                complement_points=[x for x in range(32) if sbox[x] == x ^ 31])


def rotr(x, shift, width):
    shift %= width
    return ((x >> shift) | (x << (width - shift))) & ((1 << width) - 1)


def matrix_inverse(width, ra, rb):
    columns = [(1 << j) ^ rotr(1 << j, ra, width) ^ rotr(1 << j, rb, width)
               for j in range(width)]
    rows = [sum(((columns[j] >> i) & 1) << j for j in range(width)) |
            (1 << (width + i)) for i in range(width)]
    rank = 0
    for col in range(width):
        pivot = next((i for i in range(rank, width) if rows[i] & (1 << col)), None)
        if pivot is None:
            continue
        rows[rank], rows[pivot] = rows[pivot], rows[rank]
        for i in range(width):
            if i != rank and rows[i] & (1 << col):
                rows[i] ^= rows[rank]
        rank += 1
    assert rank == width
    inverses = [r >> width for r in rows]
    for j, column in enumerate(columns):
        assert sum(parity(row & column) << i for i, row in enumerate(inverses)) == 1 << j
    inverse_column_weight = sum((row & 1) != 0 for row in inverses)
    return dict(rank=rank, impulse_weight=weight(columns[0]),
                inverse_impulse_weight=inverse_column_weight), inverses


def permutation(s, rounds, width, sbox, rc, rots, inverse_rows=None):
    s = list(s)
    mask = (1 << width) - 1
    for r in (reversed(range(rounds)) if inverse_rows is not None else range(rounds)):
        if inverse_rows is not None:
            s = [sum(parity(row & s[k]) << j for j, row in enumerate(inverse_rows[k]))
                 for k in range(5)]
        else:
            s[2] ^= rc[r]
        out = [0] * 5
        for j in range(width):
            v = sbox[sum(((s[k] >> j) & 1) << k for k in range(5))]
            for k in range(5):
                out[k] |= ((v >> k) & 1) << j
        s = out
        if inverse_rows is not None:
            s[2] ^= rc[r]
        else:
            s = [(s[k] ^ rotr(s[k], rots[k][0], width) ^
                  rotr(s[k], rots[k][1], width)) & mask for k in range(5)]
    return s


def main():
    sbox, rc, rots = constants()
    metrics = sbox_metrics(sbox)
    assert metrics["differential_uniformity"] == 2
    assert metrics["max_abs_walsh"] == 12 and metrics["nonlinearity"] == 10
    assert set(metrics["component_degrees"]) == {4}
    # Positive control: the same measurement must detect the identity S-box.
    identity = sbox_metrics(list(range(32)))
    assert identity["differential_uniformity"] == identity["max_abs_walsh"] == 32
    layers, oracle = {}, []
    inverse_sbox = [sbox.index(x) for x in range(32)]
    for width in [64, 128]:
        results = [matrix_inverse(width, a, b) for a, b in rots[width]]
        layers[str(width * 5)] = [x[0] for x in results]
        # With nonzero columns counted, branch number is exactly 4:
        # 1->>=3 (three distinct rotations); 2->1 impossible since every
        # inverse single-lane impulse weighs >=3; 3->>=1; >=4->>=1.
        assert all(x[0]["impulse_weight"] == 3 and x[0]["inverse_impulse_weight"] >= 3
                   for x in results)
        inv_rows = [x[1] for x in results]
        for rounds in [0, 1, 2, 3, 4, 8, 12, 16]:
            states = [[0] * 5, [(1 << width) - 1] * 5,
                      [(0x9e3779b97f4a7c15 * (k + 1)) & ((1 << width) - 1) for k in range(5)]]
            for state in states:
                out = permutation(state, rounds, width, sbox, rc, rots[width])
                assert permutation(out, rounds, width, inverse_sbox, rc, rots[width], inv_rows) == state
                oracle.append(dict(width=width * 5, rounds=rounds,
                                   input=[hex(x) for x in state], output=[hex(x) for x in out]))
    print(json.dumps(dict(schema=1, kind="exact_components", sbox=metrics,
                         identity_control_detected=True, linear_layers=layers,
                         column_branch_number=4, oracle=oracle), sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
