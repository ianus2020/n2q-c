import json
from pathlib import Path

root = Path('/audit/source/fuzz/corpus')
result = {'mode_variants': [], 'convergent_profiles': [], 'capacity_boundaries': []}
for target, variants, offset in [('modes_roundtrip', 8, 50), ('convergent', 2, 18)]:
    for variant in range(variants):
        bits, empty_positions, large_positions = set(), set(), set()
        tag = 32 if target == 'modes_roundtrip' and variant & 1 else 16
        for path in (root/target).glob('mutation-*'):
            data = path.read_bytes()
            if data[0] != variant:
                continue
            position = int.from_bytes(data[2:4], 'big')
            bits.add(data[4] & 7)
            size = len(data)-offset
            if size == 0:
                empty_positions.add(position)
            if size == 4046:
                large_positions.add(position)
        assert bits == set(range(8)), (target, variant, bits)
        assert empty_positions == set(range(tag)), (target, variant)
        clen = 4046+tag
        assert large_positions == {0, clen//2, clen-1}, (target, variant)
        item = {'variant': variant, 'bit_choices': sorted(bits),
                'empty_tag_bytes': len(empty_positions), 'large_positions': sorted(large_positions)}
        result['mode_variants' if target == 'modes_roundtrip' else 'convergent_profiles'].append(item)
for fast in (0, 1):
    for size in (0, 1, 16, 33, 256, 4046):
        values = {int.from_bytes(p.read_bytes()[5:7], 'big')
                  for p in (root/'convergent').glob(f'capacity-{fast}-{size}-*')}
        assert values == {0, max(0, size-1), size, size+15}, (fast, size, values)
        result['capacity_boundaries'].append({'fast': fast, 'plaintext_length': size,
                                              'controls': sorted(values)})
result['status'] = 'passed'
result['limitations'] = 'Seed coordinate coverage, not all tag-byte/bit combinations or cryptographic proof.'
print(json.dumps(result, indent=2))
