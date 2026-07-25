import n2qc, os, tempfile

fails = 0
def check(name, got, exp):
    global fails
    ok = got == exp
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    if not ok:
        fails += 1
        print(f"     got {got}\n     exp {exp}")

KEY = bytes.fromhex("00112233445566778899aabbccddeeff")
KEY32 = bytes.fromhex("00112233445566778899aabbccddeeff0f1e2d3c4b5a6978"
                      "8796a5b4c3d2e1f0")
NONCE = bytes([0xa5]) * 16

print("N2Q Python reference — KAT cross-check (vs Rust/C)")

# permutation
s = n2qc.permute([0, 0, 0, 0, 0], 12, 64)
check("QP-320 zero p^12", [hex(x) for x in s],
      [hex(x) for x in [0x6c3d34cc09474fbb, 0x4ad0c1e3cc099b31, 0xe4493f2ea310ec56,
                        0x4e5d2d1f0f612aa3, 0xa629041fa88cbba2]])

# modes
check("128 hash(\"\") Secure", n2qc.hash(128, n2qc.SECURE, b"").hex(),
      "5349a47ebb78bb4a403a518a28f86740ddfd96a880f72ea6ada15a1656072bed")
check("128 seal Secure", n2qc.seal(128, n2qc.SECURE, KEY, NONCE, b"header", b"hello n2q-c").hex(),
      "44c28948f18c37050af8cc5ece767a954c74546878cf40b5053c57")
check("128 seal Fast", n2qc.seal(128, n2qc.FAST, KEY, NONCE, b"header", b"hello n2q-c").hex(),
      "e0328e3fdecb1cfe6cc102e8fec37933606966d993cdecf8f20ea0")
check("128 blind_index", n2qc.blind_index(128, n2qc.SECURE, KEY, b"alice@x.com").hex(),
      "15b058f9a3b1f5935899d03ac71ba415")
check("256 hash(\"abc\") Secure", n2qc.hash(256, n2qc.SECURE, b"abc").hex(),
      "8d3bbe5cb8f1c4b0158aabdaf1881ff050fda245352efdf0106b1b4664861b72"
      "43597d460e32661cb56f1399f619219e8122cc474e90fd3d2e9c03a3b6947fb3")
check("256 seal Fast", n2qc.seal(256, n2qc.FAST, KEY32, NONCE, b"header", b"hello n2q-c").hex(),
      "c885b4aa03afcc4a2c42b39d240f578fc9bebcb9e0459528624aa0d87052ce501a5ede276eb42de92b0bd0")

# round-trip + tamper + token interop
pt = b"the quick brown fox"
for prof in (n2qc.SECURE, n2qc.FAST):
    sealed = n2qc.seal(128, prof, KEY, NONCE, b"ad", pt)
    check(f"128 roundtrip prof={prof}", n2qc.open(128, prof, KEY, NONCE, b"ad", sealed), pt)

tok_s = n2qc.seal_token(128, n2qc.SECURE, KEY, NONCE, b"ad", pt)
tok_f = n2qc.seal_token(128, n2qc.FAST, KEY, NONCE, b"ad", pt)
check("token Secure opens", n2qc.open_token(128, KEY, b"ad", tok_s), pt)
check("token Fast opens (same decoder)", n2qc.open_token(128, KEY, b"ad", tok_f), pt)
check("Secure/Fast tokens differ", tok_s != tok_f, True)

# file helper
data = os.urandom(200000)  # e.g. an audio/video blob — bytes are bytes
d = tempfile.mkdtemp()
inp, enc, dec = f"{d}/in.bin", f"{d}/enc.n2q", f"{d}/out.bin"
open(inp, "wb").write(data)
n2qc.encrypt_file(128, n2qc.FAST, KEY, inp, enc)
n2qc.decrypt_file(128, KEY, enc, dec)
check("file encrypt/decrypt round-trip", open(dec, "rb").read(), data)

print("ALL PASS" if fails == 0 else f"{fails} FAILURES")
raise SystemExit(1 if fails else 0)
