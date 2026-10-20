#!/usr/bin/env python3
"""Recompute aggregate counts and timing statistics from retained raw evidence."""
import argparse
import csv
import gzip
import json
import math
import pathlib
import statistics


def lines(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def summarize(directory):
    rows = lines(directory / 'experiments.jsonl')
    assert rows[0]['quick'] is False and rows[0]['section'] == 'full'
    kinds = {}
    for row in rows[1:]:
        kinds.setdefault(row['kind'], []).append(row)
    expected = dict(table_oracle=2, avalanche=14, differential=48, linear_masks=12,
                    cube=84, rotational=10, hash_collision=12, aead=8)
    assert {k: len(v) for k,v in kinds.items()} == expected, 'incomplete experiment suite'
    timing = [r for r in lines(directory / 'timing.jsonl') if r['kind'] == 'timing']
    assert len(timing) == 8
    for row in timing:
        name = directory / row['raw_csv']
        if name.exists():
            handle = name.open()
        else:
            handle = gzip.open(str(name) + '.gz', 'rt')
        groups = [[],[]]
        with handle:
            for c, elapsed in csv.reader(handle):
                groups[int(c)].append(int(elapsed))
        assert [len(g) for g in groups] == [row['class0'], row['class1']]
        a,b = groups
        denom = math.sqrt(statistics.variance(a)/len(a) + statistics.variance(b)/len(b))
        t = (statistics.mean(a)-statistics.mean(b))/denom if denom else 0.0
        assert math.isclose(t, row['welch_t'], rel_tol=1e-9, abs_tol=1e-9)
        if row['positive_control']:
            assert abs(t) > 4.5, 'positive timing control did not trigger'
    exact = json.loads((directory / 'exact.json').read_text())
    trials = kinds['aead']
    output = dict(
        schema=1, experiment_records=len(rows), families=11,
        oracle_cases=sum(r['cases'] for r in kinds['table_oracle']),
        oracle_mismatches=sum(r['mismatches'] for r in kinds['table_oracle']),
        avalanche_input_flip_comparisons=sum(r['samples_per_input_bit']*r['width'] for r in kinds['avalanche']),
        differential_input_pairs=sum(r['samples'] for r in kinds['differential']),
        linear_sample_states=sum(r['samples'] for r in kinds['linear_masks']),
        cubes=sum(r['bases'] for r in kinds['cube']),
        cube_points=sum(r['bases']*(1<<r['dimension']) for r in kinds['cube']),
        rotational_comparisons=sum(r['trials'] for r in kinds['rotational']),
        rotational_relations=sum(r['relations'] for r in kinds['rotational']),
        hash_messages=sum(r['messages'] for r in kinds['hash_collision']),
        full_hash_collision_pairs=sum(r['full_collision_pairs'] for r in kinds['hash_collision']),
        aead_roundtrips=sum(r['roundtrips'] for r in trials),
        aead_tamper_rejections=sum(r['tamper_rejections'] for r in trials),
        random_forgery_attempts=sum(r['random_forgeries'] for r in trials),
        accepted_random_forgeries=sum(r['accepted_forgeries'] for r in trials),
        timing_samples=sum(r['samples'] for r in timing),
        timing_max_abs_t=max(abs(r['welch_t']) for r in timing if not r['positive_control']),
        timing_positive_min_abs_t=min(abs(r['welch_t']) for r in timing if r['positive_control']),
        sbox={k:exact['sbox'][k] for k in ['differential_uniformity','nonlinearity','max_abs_walsh','boomerang_uniformity']},
        full_round_avalanche=[r for r in kinds['avalanche'] if r['rounds'] in (8,16)],
        full_round_linear=[r for r in kinds['linear_masks'] if r['rounds'] in (8,16)],
        sat=lines(directory / 'trails.jsonl'),
        limits='Finite synthetic experiments; no whole-cipher proof or independent external audit.')
    return output


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('directory', type=pathlib.Path)
    args = parser.parse_args()
    print(json.dumps(summarize(args.directory), indent=2, sort_keys=True))
