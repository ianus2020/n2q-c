// N2Q-C reference implementation (Go) — N2Q-128 suite (QP-320).
//
// Byte-exact with the Rust, C, and Python references (see the self-test in
// main()). The N2Q-256 suite (QP-640) follows the identical structure over a
// 128-bit lane type. Research artifact — NOT audited, NOT for real data.
package main

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"os"
)

var sbox = [32]byte{
	0x1b, 0x04, 0x0d, 0x06, 0x1f, 0x1c, 0x10, 0x0e, 0x03, 0x15, 0x17, 0x13, 0x14, 0x0f, 0x0b, 0x11,
	0x01, 0x08, 0x05, 0x19, 0x18, 0x16, 0x00, 0x0a, 0x0c, 0x1e, 0x02, 0x07, 0x1a, 0x12, 0x1d, 0x09,
}
var rots = [5][2]uint{{38, 55}, {1, 23}, {23, 36}, {16, 14}, {20, 46}}
var rc = [16]byte{0x15, 0xe3, 0x2d, 0xa2, 0x5e, 0x5c, 0xab, 0xae, 0xc8, 0x9b, 0xb6, 0xb3, 0xeb, 0xbf, 0xd9, 0xf2}

const (
	Secure = 16
	Fast   = 8
	B      = 8 // rate bytes (QP-320)

	domHash   = 1
	domMAC    = 2
	domEnc    = 3
	domBI     = 4
	domStream = 5
)

func rotr(x uint64, r uint) uint64 { return bits.RotateLeft64(x, -int(r)) }

// permute applies `rounds` rounds of QP-320 to the 5-lane state.
func permute(s [5]uint64, rounds int) [5]uint64 {
	for i := 0; i < rounds; i++ {
		s[2] ^= uint64(rc[i]) // pC
		var out [5]uint64     // pS: 5-bit S-box per bit-column
		for j := 0; j < 64; j++ {
			col := (s[0]>>j)&1 | ((s[1]>>j)&1)<<1 | ((s[2]>>j)&1)<<2 | ((s[3]>>j)&1)<<3 | ((s[4]>>j)&1)<<4
			o := sbox[col]
			for k := 0; k < 5; k++ {
				out[k] |= uint64((o>>k)&1) << j
			}
		}
		s = out
		for k := 0; k < 5; k++ { // pL
			s[k] ^= rotr(s[k], rots[k][0]) ^ rotr(s[k], rots[k][1])
		}
	}
	return s
}

func pad(msg []byte) []byte {
	m := append([]byte{}, msg...)
	m = append(m, 0x01)
	for len(m)%B != 0 {
		m = append(m, 0)
	}
	m[len(m)-1] |= 0x80
	return m
}

func absorb(s [5]uint64, msg []byte, r int) [5]uint64 {
	p := pad(msg)
	for o := 0; o < len(p); o += B {
		s[0] ^= binary.LittleEndian.Uint64(p[o : o+B])
		s = permute(s, r)
	}
	return s
}

func squeeze(s [5]uint64, n, r int) []byte {
	out := make([]byte, 0, n)
	buf := make([]byte, B)
	for len(out) < n {
		binary.LittleEndian.PutUint64(buf, s[0])
		out = append(out, buf...)
		s = permute(s, r)
	}
	return out[:n]
}

func Hash(r int, msg []byte) []byte {
	s := [5]uint64{}
	s[4] ^= domHash
	s = permute(s, r)
	s = absorb(s, msg, r)
	return squeeze(s, 32, r)
}

func mac(r int, key, data []byte, dom byte) []byte {
	s := [5]uint64{}
	s[1] = binary.LittleEndian.Uint64(key[0:8])
	s[2] = binary.LittleEndian.Uint64(key[8:16])
	s[4] ^= uint64(dom)
	s = permute(s, r)
	s = absorb(s, data, r)
	return squeeze(s, 16, r)
}

func keystream(r int, key, v []byte, n int) []byte {
	s := [5]uint64{}
	s[1] = binary.LittleEndian.Uint64(key[0:8])
	s[2] = binary.LittleEndian.Uint64(key[8:16])
	s[3] = binary.LittleEndian.Uint64(v[0:8])
	s[4] = binary.LittleEndian.Uint64(v[8:16]) ^ domEnc
	s = permute(s, r)
	return squeeze(s, n, r)
}

func sivInput(nonce, ad, pt []byte) []byte {
	out := append([]byte{}, nonce...)
	var l [8]byte
	binary.LittleEndian.PutUint64(l[:], uint64(len(ad)))
	out = append(out, l[:]...)
	out = append(out, ad...)
	binary.LittleEndian.PutUint64(l[:], uint64(len(pt)))
	out = append(out, l[:]...)
	return append(out, pt...)
}

// Seal encrypts under the given profile (Secure or Fast). Returns tag ‖ ct.
func Seal(profile int, key, nonce, ad, pt []byte) []byte {
	v := mac(profile, key, sivInput(nonce, ad, pt), domMAC)
	ks := keystream(profile, key, v, len(pt))
	out := append([]byte{}, v...)
	for i := range pt {
		out = append(out, pt[i]^ks[i])
	}
	return out
}

// Open decrypts; returns (plaintext, true) or (nil, false) on auth failure.
func Open(profile int, key, nonce, ad, sealed []byte) ([]byte, bool) {
	if len(sealed) < 16 {
		return nil, false
	}
	v, ct := sealed[:16], sealed[16:]
	ks := keystream(profile, key, v, len(ct))
	pt := make([]byte, len(ct))
	for i := range ct {
		pt[i] = ct[i] ^ ks[i]
	}
	v2 := mac(profile, key, sivInput(nonce, ad, pt), domMAC)
	if ctEq(v, v2) {
		return pt, true
	}
	return nil, false
}

func BlindIndex(profile int, key, value []byte) []byte { return mac(profile, key, value, domBI) }

func ctEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var acc byte
	for i := range a {
		acc |= a[i] ^ b[i]
	}
	return acc == 0
}

// SealToken → self-describing "nqc." token (records mode+size+profile).
func SealToken(profile int, key, nonce, ad, pt []byte) string {
	suite := byte(0x01)
	if profile == Fast {
		suite |= 0x20
	}
	raw := append([]byte{1, suite}, nonce...)
	raw = append(raw, Seal(profile, key, nonce, ad, pt)...)
	return "nqc." + base64.RawURLEncoding.EncodeToString(raw)
}

// OpenToken reads the profile+nonce from the token and decrypts.
func OpenToken(key, ad []byte, token string) ([]byte, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(token[4:])
	if err != nil || len(raw) < 18 {
		return nil, false
	}
	profile := Secure
	if raw[1]&0x20 != 0 {
		profile = Fast
	}
	return Open(profile, key, raw[2:18], ad, raw[18:])
}

// ===================== N2Q-256 (QP-640) — 128-bit lanes via u128 =============

var rots640 = [5][2]uint{{75, 7}, {89, 21}, {56, 111}, {30, 54}, {25, 52}}

const B256 = 16

type u128 struct{ hi, lo uint64 }

func shl128(x u128, n uint) u128 {
	if n == 0 {
		return x
	}
	if n < 64 {
		return u128{(x.hi << n) | (x.lo >> (64 - n)), x.lo << n}
	}
	return u128{x.lo << (n - 64), 0}
}
func shr128(x u128, n uint) u128 {
	if n == 0 {
		return x
	}
	if n < 64 {
		return u128{x.hi >> n, (x.lo >> n) | (x.hi << (64 - n))}
	}
	return u128{0, x.hi >> (n - 64)}
}
func (x u128) xor(y u128) u128 { return u128{x.hi ^ y.hi, x.lo ^ y.lo} }
func (x u128) rotr(r uint) u128 {
	r %= 128
	if r == 0 {
		return x
	}
	a, b := shr128(x, r), shl128(x, 128-r)
	return u128{a.hi | b.hi, a.lo | b.lo}
}
func (x u128) bit(j int) uint64 {
	if j < 64 {
		return (x.lo >> uint(j)) & 1
	}
	return (x.hi >> uint(j-64)) & 1
}
func setbit(x *u128, j int, v uint64) {
	if j < 64 {
		x.lo |= v << uint(j)
	} else {
		x.hi |= v << uint(j-64)
	}
}
func le128(b []byte) u128 { return u128{binary.LittleEndian.Uint64(b[8:16]), binary.LittleEndian.Uint64(b[0:8])} }
func put128(x u128) []byte {
	b := make([]byte, 16)
	binary.LittleEndian.PutUint64(b[0:8], x.lo)
	binary.LittleEndian.PutUint64(b[8:16], x.hi)
	return b
}

func permute640(s [5]u128, rounds int) [5]u128 {
	for i := 0; i < rounds; i++ {
		s[2] = s[2].xor(u128{0, uint64(rc[i])}) // pC
		var out [5]u128                         // pS
		for j := 0; j < 128; j++ {
			col := s[0].bit(j) | s[1].bit(j)<<1 | s[2].bit(j)<<2 | s[3].bit(j)<<3 | s[4].bit(j)<<4
			o := sbox[col]
			for k := 0; k < 5; k++ {
				setbit(&out[k], j, uint64((o>>k)&1))
			}
		}
		s = out
		for k := 0; k < 5; k++ { // pL
			s[k] = s[k].xor(s[k].rotr(rots640[k][0])).xor(s[k].rotr(rots640[k][1]))
		}
	}
	return s
}

func pad256(msg []byte) []byte {
	m := append([]byte{}, msg...)
	m = append(m, 0x01)
	for len(m)%B256 != 0 {
		m = append(m, 0)
	}
	m[len(m)-1] |= 0x80
	return m
}
func absorb256(s [5]u128, msg []byte, r int) [5]u128 {
	p := pad256(msg)
	for o := 0; o < len(p); o += B256 {
		s[0] = s[0].xor(le128(p[o : o+B256]))
		s = permute640(s, r)
	}
	return s
}
func squeeze256(s [5]u128, n, r int) []byte {
	out := make([]byte, 0, n)
	for len(out) < n {
		out = append(out, put128(s[0])...)
		s = permute640(s, r)
	}
	return out[:n]
}
func Hash256(r int, msg []byte) []byte {
	s := [5]u128{}
	s[4] = s[4].xor(u128{0, 1}) // DOM_HASH
	s = permute640(s, r)
	return squeeze256(absorb256(s, msg, r), 64, r)
}
func mac256(r int, key, data []byte, dom byte) []byte {
	s := [5]u128{}
	s[1] = le128(key[0:16])
	s[2] = le128(key[16:32])
	s[4] = s[4].xor(u128{0, uint64(dom)})
	s = permute640(s, r)
	return squeeze256(absorb256(s, data, r), 32, r)
}
func keystream256(r int, key, v []byte, n int) []byte {
	s := [5]u128{}
	s[1] = le128(key[0:16])
	s[2] = le128(key[16:32])
	s[3] = le128(v[0:16])
	s[4] = le128(v[16:32]).xor(u128{0, 3}) // DOM_ENC
	s = permute640(s, r)
	return squeeze256(s, n, r)
}
func Seal256(profile int, key, nonce, ad, pt []byte) []byte {
	v := mac256(profile, key, sivInput(nonce, ad, pt), 2)
	ks := keystream256(profile, key, v, len(pt))
	out := append([]byte{}, v...)
	for i := range pt {
		out = append(out, pt[i]^ks[i])
	}
	return out
}
func Open256(profile int, key, nonce, ad, sealed []byte) ([]byte, bool) {
	if len(sealed) < 32 {
		return nil, false
	}
	v, ct := sealed[:32], sealed[32:]
	ks := keystream256(profile, key, v, len(ct))
	pt := make([]byte, len(ct))
	for i := range ct {
		pt[i] = ct[i] ^ ks[i]
	}
	if ctEq(v, mac256(profile, key, sivInput(nonce, ad, pt), 2)) {
		return pt, true
	}
	return nil, false
}
func BlindIndex256(profile int, key, value []byte) []byte { return mac256(profile, key, value, 4) }

// ===================== N2QF binary file container =============================
// Layout:  "N2QF" | version(1) | suite(1) | { le32(len) | sealed(tag||ct) }*
// nonce for chunk i = 16-byte little-endian i (deterministic → not stored).
const chunkSize = 1 << 16

func EncryptFile(profile int, key []byte, inPath, outPath string) error {
	bits := 128
	suite := byte(0x01)
	if len(key) == 32 {
		bits, suite = 256, 0x02
	}
	if profile == Fast {
		suite |= 0x20
	}
	fi, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer fi.Close()
	fo, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer fo.Close()
	fo.Write([]byte{'N', '2', 'Q', 'F', 1, suite})
	buf := make([]byte, chunkSize)
	var idx uint64
	var l [4]byte
	for {
		n, e := fi.Read(buf)
		if n > 0 {
			nonce := make([]byte, 16)
			binary.LittleEndian.PutUint64(nonce, idx)
			var sealed []byte
			if bits == 128 {
				sealed = Seal(profile, key, nonce, nil, buf[:n])
			} else {
				sealed = Seal256(profile, key, nonce, nil, buf[:n])
			}
			binary.LittleEndian.PutUint32(l[:], uint32(len(sealed)))
			fo.Write(l[:])
			fo.Write(sealed)
			idx++
		}
		if e != nil {
			break
		}
	}
	return nil
}

func DecryptFile(key []byte, inPath, outPath string) error {
	fi, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer fi.Close()
	fo, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer fo.Close()
	hdr := make([]byte, 6)
	if _, err := io.ReadFull(fi, hdr); err != nil || string(hdr[:4]) != "N2QF" {
		return errors.New("not an N2QF file")
	}
	suite := hdr[5]
	bits, profile := 128, Secure
	if suite&0x0f == 2 {
		bits = 256
	}
	if suite&0x20 != 0 {
		profile = Fast
	}
	var idx uint64
	var l [4]byte
	for {
		if _, e := io.ReadFull(fi, l[:]); e != nil {
			break
		}
		sealed := make([]byte, binary.LittleEndian.Uint32(l[:]))
		if _, e := io.ReadFull(fi, sealed); e != nil {
			return errors.New("truncated container")
		}
		nonce := make([]byte, 16)
		binary.LittleEndian.PutUint64(nonce, idx)
		var pt []byte
		var ok bool
		if bits == 128 {
			pt, ok = Open(profile, key, nonce, nil, sealed)
		} else {
			pt, ok = Open256(profile, key, nonce, nil, sealed)
		}
		if !ok {
			return fmt.Errorf("authentication failed (chunk %d)", idx)
		}
		fo.Write(pt)
		idx++
	}
	return nil
}

func hx(b []byte) string { s := ""; for _, x := range b { s += fmt.Sprintf("%02x", x) }; return s }

func main() {
	// CLI file mode:  go run . encrypt|decrypt <in> <out>   (fixed demo key)
	if len(os.Args) == 4 && (os.Args[1] == "encrypt" || os.Args[1] == "decrypt") {
		key := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
		var err error
		if os.Args[1] == "encrypt" {
			err = EncryptFile(Fast, key, os.Args[2], os.Args[3])
		} else {
			err = DecryptFile(key, os.Args[2], os.Args[3])
		}
		if err != nil {
			fmt.Println("error:", err)
			os.Exit(1)
		}
		return
	}

	fails := 0
	check := func(name, got, exp string) {
		ok := got == exp
		st := "PASS"
		if !ok {
			st, fails = "FAIL", fails+1
		}
		fmt.Printf("  [%s] %s\n", st, name)
		if !ok {
			fmt.Printf("     got %s\n     exp %s\n", got, exp)
		}
	}
	key := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	nonce := make([]byte, 16)
	for i := range nonce {
		nonce[i] = 0xa5
	}

	fmt.Println("N2Q-C Go reference — KAT cross-check (vs Rust/C/Python)")
	s := permute([5]uint64{}, 12)
	check("QP-320 zero p^12", fmt.Sprintf("%016x %016x", s[0], s[1]), "6c3d34cc09474fbb 4ad0c1e3cc099b31")
	check("hash(\"\") Secure", hx(Hash(Secure, []byte(""))), "5349a47ebb78bb4a403a518a28f86740ddfd96a880f72ea6ada15a1656072bed")
	check("seal Secure", hx(Seal(Secure, key, nonce, []byte("header"), []byte("hello n2q-c"))), "44c28948f18c37050af8cc5ece767a954c74546878cf40b5053c57")
	check("seal Fast", hx(Seal(Fast, key, nonce, []byte("header"), []byte("hello n2q-c"))), "e0328e3fdecb1cfe6cc102e8fec37933606966d993cdecf8f20ea0")
	check("blind_index", hx(BlindIndex(Secure, key, []byte("alice@x.com"))), "15b058f9a3b1f5935899d03ac71ba415")

	// token interoperability
	pt := []byte("the quick brown fox")
	ts := SealToken(Secure, key, nonce, []byte("ad"), pt)
	tf := SealToken(Fast, key, nonce, []byte("ad"), pt)
	ds, _ := OpenToken(key, []byte("ad"), ts)
	df, _ := OpenToken(key, []byte("ad"), tf)
	check("token Secure opens", string(ds), string(pt))
	check("token Fast opens (same decoder)", string(df), string(pt))

	// ---- N2Q-256 (QP-640) ----
	key32 := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0}
	s6 := permute640([5]u128{}, 12)
	check("QP-640 zero p^12", fmt.Sprintf("%016x%016x", s6[0].hi, s6[0].lo), "92d9767d204356d5bf69412869804a6a")
	check("256 hash(\"abc\") Secure", hx(Hash256(Secure, []byte("abc"))),
		"8d3bbe5cb8f1c4b0158aabdaf1881ff050fda245352efdf0106b1b4664861b7243597d460e32661cb56f1399f619219e8122cc474e90fd3d2e9c03a3b6947fb3")
	check("256 seal Secure", hx(Seal256(Secure, key32, nonce, []byte("header"), []byte("hello n2q-c"))),
		"0fc0b54697f0dd3cce390382e15918473bd858843f0957b958a6cafe95c01f5e10e8d7ad55996a2bfd1037")
	check("256 seal Fast", hx(Seal256(Fast, key32, nonce, []byte("header"), []byte("hello n2q-c"))),
		"c885b4aa03afcc4a2c42b39d240f578fc9bebcb9e0459528624aa0d87052ce501a5ede276eb42de92b0bd0")
	check("256 blind_index", hx(BlindIndex256(Secure, key32, []byte("alice@x.com"))),
		"7e99c9501484b22156a3fc3c98b10f88149cfe2396b5250df737a34a4f50de75")
	pt2 := []byte("N2Q-256 streaming payload sample")
	sl2 := Seal256(Fast, key32, nonce, []byte("ad"), pt2)
	do2, ok2 := Open256(Fast, key32, nonce, []byte("ad"), sl2)
	check("256 roundtrip", fmt.Sprintf("%v %s", ok2, string(do2)), "true "+string(pt2))

	// N2QF cross-language interop: decrypt the Python-produced container
	if _, e := os.Stat("/tmp/filedemo/photo.n2q"); e == nil {
		eq := "false"
		if DecryptFile(key, "/tmp/filedemo/photo.n2q", "/tmp/filedemo/photo.go.png") == nil {
			a, _ := os.ReadFile("/tmp/filedemo/photo.png")
			b, _ := os.ReadFile("/tmp/filedemo/photo.go.png")
			same := len(a) == len(b) && len(a) > 0
			for i := 0; same && i < len(a); i++ {
				if a[i] != b[i] {
					same = false
				}
			}
			if same {
				eq = "true"
			}
		}
		check("N2QF cross-decrypt (Python -> Go)", eq, "true")
	}

	fails += modesCross() // extended-modes cross-check (Python -> Go)

	if fails == 0 {
		fmt.Println("ALL PASS")
	} else {
		fmt.Printf("%d FAILURES\n", fails)
		os.Exit(1)
	}
}
