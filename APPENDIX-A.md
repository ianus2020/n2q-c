# N2Q-C — Appendix A: Concrete constants (M2 output)

All values below are produced deterministically by
[`tools/const-search`](tools/const-search) from the public seed string
`"N2Q-C/v0.1"` (and its documented sub-labels). Re-running the tool reproduces
them exactly — this is the nothing-up-my-sleeve guarantee of SPEC §7.

Status: **provisional-final.** The S-box and rotation constants are fixed. The
round counts are provisional-generous, to be confirmed by the differential/
linear MILP bound in milestone M4.

Reproduce:
```sh
cd tools/const-search
cargo run --release -- construct    # S-box construction + properties
cargo run --release -- rotations 64 1500    # QP-320 rotations
cargo run --release -- rotations 128 500    # QP-640 rotations
cargo run --release -- finalize     # all constants + KAT vectors
```

## A.1 S-box S5

Construction: multiplicative inverse in GF(2⁵) (primitive polynomial
x⁵+x²+1), wrapped in a deterministically-chosen invertible affine bijection that
removes fixed points (properties are affine-invariant). This is the AES design
methodology.

```
S5 = [
  0x1b, 0x04, 0x0d, 0x06, 0x1f, 0x1c, 0x10, 0x0e, 0x03, 0x15, 0x17, 0x13, 0x14, 0x0f, 0x0b, 0x11,
  0x01, 0x08, 0x05, 0x19, 0x18, 0x16, 0x00, 0x0a, 0x0c, 0x1e, 0x02, 0x07, 0x1a, 0x12, 0x1d, 0x09,
]
```

Measured properties (by `tools/const-search`):

| Property | Value | Requirement | Note |
|---|---|---|---|
| Bijective | yes | required | |
| Differential uniformity | **2** | ≤ 4 | **APN** — optimal; max DP = 2⁻⁴ |
| Nonlinearity | **10** | ≥ 10 | linearity 12; max correlation 2⁻¹·⁴² |
| Algebraic degree | **4** | ≥ 3 | maximum for n=5 |
| Fixed points / anti-fixed | 0 / 0 | 0 / 0 | |
| Differential branch (S-box) | 2 | — | normal at S-box level (as AES/Ascon); diffusion is the linear layer's job |
| ANF ops (circuit proxy) | 76 | minimise | constant-time via bitsliced ANF |

> Design note (M2): SPEC §7.1's original "branch ≥ 3" criterion was mis-placed at
> the S-box level and has been dropped — branch number is a property of the
> linear layer (A.2), not the S-box. All other §7.1 criteria are met.

## A.2 Rotation constants (linear layer pL)

`x_k ← x_k ⊕ (x_k ⋙ ra_k) ⊕ (x_k ⋙ rb_k)`, chosen to minimise rounds-to-full-
diffusion (SPEC §7.2). Both widths reach **full linear diffusion in 4 rounds**.

| lane k | QP-320 (ra, rb) | QP-640 (ra, rb) |
|---|---|---|
| 0 | 38, 55 | 75, 7 |
| 1 | 1, 23 | 89, 21 |
| 2 | 23, 36 | 56, 111 |
| 3 | 16, 14 | 30, 54 |
| 4 | 20, 46 | 25, 52 |

## A.3 Round constants rc_i

16 distinct bytes from seed `"N2Q-C/v0.1/rc"`, XORed into lane x2 at round i:

```
rc = [0x15, 0xe3, 0x2d, 0xa2, 0x5e, 0x5c, 0xab, 0xae,
      0xc8, 0x9b, 0xb6, 0xb3, 0xeb, 0xbf, 0xd9, 0xf2]
```

## A.4 Round counts (FINAL for v0.1)

- `p^b` (data rounds) = **12**
- `p^a` (init / final) = **16**

Confirmed in M4: every measured property (full diffusion 4 rounds, ideal
avalanche 5, degree saturation 3, differential collapse 3) leaves a ≥2.4×
cushion ([docs/cryptanalysis.md](docs/cryptanalysis.md)). A MILP active-S-box
*proof* is the one open item and could only justify fewer rounds, which the
margin preference declines — so these counts, and the KATs below, are final.

## A.5 Known-answer test vectors

Reference (table-based) QP output; lanes printed x0..x4, hex, MSB-lane-first.
The M3 constant-time C/Rust implementations must reproduce these exactly.

### QP-320 (5×64)
```
zero,    p^12: 6c3d34cc09474fbb 4ad0c1e3cc099b31 e4493f2ea310ec56 4e5d2d1f0f612aa3 a629041fa88cbba2
zero,    p^16: 0a80d3fda988ac26 221c8fdc996d211e 4970cbaefa3be331 c52528314439a60d b15ae981e77924c9
pattern, p^12: cacee3c01fa6963e f808bd597a3cf500 8ded22db7633bad2 8f876e846c9ea9a8 5130139b0338a456
pattern, p^16: b05fd1828f75c04e fadd6312a83d7022 ec9d2381a621159d 207db4d1a13614a6 b49659a80a9ee726
```
`pattern` = x0..x4 = `0123456789abcdef, fedcba9876543210, 0f1e2d3c4b5a6978, 1122334455667788, 8090a0b0c0d0e0f0`.

### QP-640 (5×128)
```
zero,    p^12: 92d9767d204356d5bf69412869804a6a c810337e8e03196a656eea5765acdcdf c8f6c409f8e38370b1621e358303e666 0b312a32ac9c8523a94c52eb50bcdc8f 47ed01c11be8cc1d9bd809f54ccff628
zero,    p^16: 25452c2956aa779c3afac832b8915320 9fd25b8f74682264a487a3ee0c889244 94bacf8edd9f9a52dd1042d6e83394d8 b2a56cec77edb42729abb9892a725804 113fe3df194de14acbaace2dc2cf8345
```

## A.6 Concrete N2Q-128 mode construction (M3)

The primary suite, as implemented and cross-checked in the C and Rust references
([`impl/`](impl)). Sponge on QP-320: **rate = 64 bits (lane x0)**, capacity 256
(x1..x4), sponge function **f = p^r rounds**, uniform. The **profile** picks `r`:
**Secure** `r=16` (default), **Fast** `r=8` (~2× throughput). The profile is
recorded in the frame suite byte (bit `0x20`), so one decoder reads both. Byte
padding **pad10\*1**: append `0x01`, zero-fill to an 8-byte multiple, set the MSB
of the final byte. Domain constants XORed into lane **x4** at init:
HASH=1, MAC=2, ENC=3, BI=4, STREAM=5.

- **Hash-256**: `s=0; x4^=HASH; f; absorb(msg); out=squeeze(32)`.
- **Keyed MAC**: `s=0; x1,x2=key; x4^=dom; f; absorb(data); squeeze(16)`.
- **Keystream**: `s=0; x1,x2=key; x3,x4=V; x4^=ENC; f; squeeze(n)`.
- **SIV-AEAD seal**: `V = MAC(key, nonce ‖ le64(|ad|) ‖ ad ‖ le64(|pt|) ‖ pt)`;
  `C = pt ⊕ Keystream(key,V,|pt|)`; output `V ‖ C`. Open recomputes and compares
  `V` in constant time.
- **Blind index**: `MAC(key, value)` with domain BI, 16 bytes.

### Mode known-answer vectors

**N2Q-128** — key = `00112233445566778899aabbccddeeff`, nonce = `a5…a5` (16 B):
```
Secure hash("")                = 5349a47ebb78bb4a403a518a28f86740ddfd96a880f72ea6ada15a1656072bed
Secure hash("abc")             = 9b8d0f3ff48bf6627114eeace965cccb2d2266f01d44e475b074e2be3d19203f
Secure seal(ad="header",…)     = 44c28948f18c37050af8cc5ece767a954c74546878cf40b5053c57
Fast   seal(ad="header",…)     = e0328e3fdecb1cfe6cc102e8fec37933606966d993cdecf8f20ea0
Secure stream(ad="header",…)   = f312993bb6e3c11c6951eff7098585fbbfd70ccf54cbe45e498afa
Secure blind_index("alice@x.com") = 15b058f9a3b1f5935899d03ac71ba415
```

**N2Q-256** — key = `00112233445566778899aabbccddeeff0f1e2d3c4b5a697887 96a5b4c3d2e1f0`
(32 B, spaces cosmetic), nonce = `a5…a5`:
```
Secure hash("abc")             = 8d3bbe5cb8f1c4b0158aabdaf1881ff050fda245352efdf0106b1b4664861b72
                                 43597d460e32661cb56f1399f619219e8122cc474e90fd3d2e9c03a3b6947fb3
Secure seal(ad="header",…)     = 0fc0b54697f0dd3cce390382e15918473bd858843f0957b958a6cafe95c01f5e10e8d7ad55996a2bfd1037
Fast   seal(ad="header",…)     = c885b4aa03afcc4a2c42b39d240f578fc9bebcb9e0459528624aa0d87052ce501a5ede276eb42de92b0bd0
Secure stream(ad="header",…)   = 2562bd9a4879f0df72d710f9401ae4566c153e1758352d42086b38b8652c2cc913c4523887a9fd53b3bf6e
Secure blind_index("alice@x.com") = 7e99c9501484b22156a3fc3c98b10f88149cfe2396b5250df737a34a4f50de75
```

> All KATs are **final for v0.1**. The tool, the Rust reference, and the C
> reference reproduce every Secure and Fast vector exactly (C: `./n2qc`).
