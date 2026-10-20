#!/usr/bin/env python3
"""Bounded all-start differential-trail SAT experiment (Z3 4.15.4.0).

Local S-box transitions are exact. Independent local preimages make this an
over-approximation of realizable multi-round pairs. UNSAT gives an active-box
lower bound within the model; SAT is a local-DDT trail, not an actual attack.
No round independence or whole-cipher security theorem is asserted.
"""
import argparse
import hashlib
import json
import pathlib
import time
import z3
from exact import constants


def sxor(parts):
    out = z3.BoolVal(False)
    for part in parts:
        out = z3.Xor(out, part)
    return out


def anf_masks(table):
    result = []
    for bit in range(5):
        tt = [(table[x] >> bit) & 1 for x in range(32)]
        for j in range(5):
            for x in range(32):
                if x & (1 << j):
                    tt[x] ^= tt[x ^ (1 << j)]
        result.append([x for x, c in enumerate(tt) if c])
    return result


def apply_anf(bits, masks):
    return [sxor([z3.And([bits[j] for j in range(5) if mask & (1 << j)])
                  for mask in component]) for component in masks]


def experiment(width, rounds, limit, timeout, directory):
    table, _, rots = constants()
    masks = anf_masks(table)
    d = [[[z3.Bool("d_%d_%d_%d" % (r,k,j)) for j in range(width)]
          for k in range(5)] for r in range(rounds)]
    solver = z3.Solver()
    solver.set(timeout=timeout, random_seed=20261019)
    activity = [z3.Or([d[r][k][j] for k in range(5)])
                for r in range(rounds) for j in range(width)]
    # All nonzero starts: cyclic symmetry permits pinning an active column to 0.
    solver.add(activity[0])
    solver.add(z3.PbLe([(a,1) for a in activity], limit))
    for r in range(rounds-1):
        after = [[z3.Bool("y_%d_%d_%d" % (r,k,j)) for j in range(width)] for k in range(5)]
        for j in range(width):
            base = [z3.Bool("base_%d_%d_%d" % (r,j,k)) for k in range(5)]
            alt = [z3.Xor(base[k], d[r][k][j]) for k in range(5)]
            a, b = apply_anf(base, masks), apply_anf(alt, masks)
            for k in range(5):
                solver.add(after[k][j] == z3.Xor(a[k], b[k]))
        for k, (ra, rb) in enumerate(rots[width]):
            for j in range(width):
                solver.add(d[r+1][k][j] == sxor([after[k][j], after[k][(j+ra)%width], after[k][(j+rb)%width]]))
    smt = solver.to_smt2().encode()
    name = "trail-%d-%dr-atmost%d" % (width*5, rounds, limit)
    (directory / (name + ".smt2")).write_bytes(smt)
    start = time.monotonic()
    status = solver.check()
    result = dict(width=width*5, rounds=rounds, active_box_limit=limit,
                  status=str(status), timeout_ms=timeout, seconds=time.monotonic()-start,
                  model_sha256=hashlib.sha256(smt).hexdigest())
    if status == z3.unknown:
        result["reason"] = solver.reason_unknown()
    if status == z3.unsat:
        result["active_box_lower_bound"] = limit+1
    if status == z3.sat:
        model = solver.model()
        values = [[[bool(z3.is_true(model.eval(d[r][k][j], model_completion=True)))
                    for j in range(width)] for k in range(5)] for r in range(rounds)]
        states = [[sum(int(values[r][k][j]) << j for j in range(width)) for k in range(5)] for r in range(rounds)]
        result["input_differences"] = [[hex(x) for x in s] for s in states]
        result["active_boxes"] = sum(sum(any(values[r][k][j] for k in range(5)) for j in range(width)) for r in range(rounds))
        assert 0 < result["active_boxes"] <= limit
        # Independent check of every S-box transition using an inverse pL.
        from exact import matrix_inverse, parity
        inv = [matrix_inverse(width, a,b)[1] for a,b in rots[width]]
        for r in range(rounds-1):
            after = [sum(parity(row & states[r+1][k]) << j for j,row in enumerate(inv[k])) for k in range(5)]
            for j in range(width):
                a = sum(((states[r][k]>>j)&1)<<k for k in range(5))
                b = sum(((after[k]>>j)&1)<<k for k in range(5))
                assert any(table[x] ^ table[x^a] == b for x in range(32))
        result["witness_ddt_verified"] = True
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeout-ms", type=int, default=15000)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    print(json.dumps(dict(kind="sat_metadata", z3=z3.get_version_string(),
                          scope="all-start locally DDT-admissible differential trails, 2-4 rounds")), flush=True)
    for width in [64,128]:
        for rounds, limit in [(2,3), (3,5), (3,6), (4,8)]:
            print(json.dumps(experiment(width, rounds, limit, args.timeout_ms, args.output)), flush=True)


if __name__ == "__main__":
    main()
