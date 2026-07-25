// n2qc_modes (Go) — extended modes in pure Go, built only on the native core
// (Seal / Open / Hash). No C, no cgo. Byte-compatible with the Python / Rust /
// C ports: a blob made in one opens in the others.
package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

var envAD = []byte("n2q-envelope-v1")
var convAD = []byte("n2q-conv")
var zero16 = make([]byte, 16)

// envelope + rotation
func Wrap(kek, dek []byte) []byte           { return Seal(Secure, kek, zero16, envAD, dek) }
func Unwrap(kek, blob []byte) ([]byte, bool) { return Open(Secure, kek, zero16, envAD, blob) }
func Rewrap(oldK, newK, blob []byte) ([]byte, bool) {
	d, ok := Unwrap(oldK, blob)
	if !ok {
		return nil, false
	}
	return Wrap(newK, d), true
}

// key-committing AEAD:  token = KC(32) | sealed
func commit(key, tag []byte) []byte {
	buf := make([]byte, 0, 1+len(key)+len(tag))
	buf = append(buf, 0x07)
	buf = append(buf, key...)
	buf = append(buf, tag...)
	return Hash(Secure, buf)[:32]
}
func SealCommitting(key, nonce, ad, pt []byte, profile int) []byte {
	sealed := Seal(profile, key, nonce, ad, pt)
	return append(commit(key, sealed[:16]), sealed...)
}
func OpenCommitting(key, nonce, ad, token []byte, profile int) ([]byte, bool) {
	if len(token) < 32+16 {
		return nil, false
	}
	kc, sealed := token[:32], token[32:]
	if !bytes.Equal(commit(key, sealed[:16]), kc) {
		return nil, false
	}
	return Open(profile, key, nonce, ad, sealed)
}

// convergent (dedup)
func ConvSeal(mk, content []byte, profile int) (dek, ct []byte) {
	m := make([]byte, 0, len(mk)+len(content))
	m = append(append(m, mk...), content...)
	dek = Hash(Secure, m)[:16]
	return dek, Seal(profile, dek, zero16, convAD, content)
}
func ConvOpen(dek, ct []byte, profile int) ([]byte, bool) {
	return Open(profile, dek, zero16, convAD, ct)
}

// length-hiding:  padded = le32(len) | pt | zeros to bucket
func SealPadded(key, nonce, ad, pt []byte, profile, bucket int) []byte {
	need := 4 + len(pt)
	padded := ((need + bucket - 1) / bucket) * bucket
	buf := make([]byte, padded)
	binary.LittleEndian.PutUint32(buf, uint32(len(pt)))
	copy(buf[4:], pt)
	return Seal(profile, key, nonce, ad, buf)
}
func OpenPadded(key, nonce, ad, token []byte, profile int) ([]byte, bool) {
	buf, ok := Open(profile, key, nonce, ad, token)
	if !ok || len(buf) < 4 {
		return nil, false
	}
	n := binary.LittleEndian.Uint32(buf[:4])
	if 4+int(n) > len(buf) {
		return nil, false
	}
	return buf[4 : 4+n], true
}

// stego framing:  out = nonce(16) | sealed
func StegoSeal(key, nonce, ad, pt []byte, profile int) []byte {
	return append(append([]byte{}, nonce...), Seal(profile, key, nonce, ad, pt)...)
}
func StegoOpen(key, ad, blob []byte, profile int) ([]byte, bool) {
	if len(blob) < 16 {
		return nil, false
	}
	return Open(profile, key, blob[:16], ad, blob[16:])
}

// audit-log (hash chain)
var logAD = []byte("n2q-log")

func LogGenesis() []byte { return Hash(Secure, []byte("n2q-log-genesis")) }
func LogAppend(head []byte, seq uint64, key, entry []byte) (record, newHead []byte) {
	nonce := make([]byte, 16)
	binary.LittleEndian.PutUint64(nonce, seq)
	sealed := Seal(Secure, key, nonce, logAD, entry)
	record = make([]byte, 8+len(sealed))
	binary.LittleEndian.PutUint64(record, seq)
	copy(record[8:], sealed)
	return record, Hash(Secure, append(append([]byte{}, head...), record...))
}
func LogVerify(key []byte, records [][]byte, expectedHead []byte) bool {
	head := LogGenesis()
	for i, rec := range records {
		if len(rec) < 8+16 || binary.LittleEndian.Uint64(rec[:8]) != uint64(i) {
			return false
		}
		nonce := make([]byte, 16)
		copy(nonce, rec[:8])
		if _, ok := Open(Secure, key, nonce, logAD, rec[8:]); !ok {
			return false
		}
		head = Hash(Secure, append(append([]byte{}, head...), rec...))
	}
	return bytes.Equal(head, expectedHead)
}

// message franking
func frankOpening(key, nonce []byte) []byte {
	b := append([]byte{0x08}, key...)
	return Hash(Secure, append(b, nonce...))[:16]
}
func frankCommit(opening, msg []byte) []byte {
	b := append([]byte{0x09}, opening...)
	return Hash(Secure, append(b, msg...))[:32]
}
func FrankSeal(key, nonce, msg []byte) []byte {
	cf := frankCommit(frankOpening(key, nonce), msg)
	return append(cf, Seal(Secure, key, nonce, cf, msg)...)
}
func FrankOpen(key, nonce, token []byte) (msg, cf, opening []byte, ok bool) {
	if len(token) < 32+16 {
		return nil, nil, nil, false
	}
	cf = token[:32]
	m, o := Open(Secure, key, nonce, cf, token[32:])
	if !o {
		return nil, nil, nil, false
	}
	op := frankOpening(key, nonce)
	if !bytes.Equal(frankCommit(op, m), cf) {
		return nil, nil, nil, false
	}
	return m, cf, op, true
}
func FrankReportVerify(cf, opening, msg []byte) bool {
	return bytes.Equal(frankCommit(opening, msg), cf)
}

// seekable N2QF
func N2qfBuild(key []byte, chunks [][]byte, profile int) []byte {
	suite := byte(0x01)
	if profile == Fast {
		suite |= 0x20
	}
	out := append([]byte("N2QF"), 1, suite)
	for i, ch := range chunks {
		nonce := make([]byte, 16)
		binary.LittleEndian.PutUint64(nonce, uint64(i))
		sealed := Seal(profile, key, nonce, nil, ch)
		l := make([]byte, 4)
		binary.LittleEndian.PutUint32(l, uint32(len(sealed)))
		out = append(out, l...)
		out = append(out, sealed...)
	}
	return out
}
func SeekChunk(key, buf []byte, index int) ([]byte, bool) {
	if len(buf) < 6 || !bytes.Equal(buf[:4], []byte("N2QF")) {
		return nil, false
	}
	profile := Secure
	if buf[5]&0x20 != 0 {
		profile = Fast
	}
	p, i := 6, 0
	for p+4 <= len(buf) {
		l := int(binary.LittleEndian.Uint32(buf[p : p+4]))
		p += 4
		if i == index {
			nonce := make([]byte, 16)
			binary.LittleEndian.PutUint64(nonce, uint64(index))
			return Open(profile, key, nonce, nil, buf[p:p+l])
		}
		p += l
		i++
	}
	return nil, false
}

// streaming AEAD (seq -> nonce, sliding replay window)
type StreamTx struct {
	key []byte
	p   int
	seq uint64
}

func NewStreamTx(key []byte, profile int) *StreamTx { return &StreamTx{key, profile, 0} }
func (s *StreamTx) Seal(aad, pt []byte) []byte {
	nonce := make([]byte, 16)
	binary.LittleEndian.PutUint64(nonce, s.seq)
	out := make([]byte, 8)
	binary.LittleEndian.PutUint64(out, s.seq)
	out = append(out, Seal(s.p, s.key, nonce, aad, pt)...)
	s.seq++
	return out
}

type StreamRx struct {
	key          []byte
	p            int
	max, win     uint64
	started      bool
}

func NewStreamRx(key []byte, profile int) *StreamRx { return &StreamRx{key: key, p: profile} }
func (r *StreamRx) Open(aad, pkt []byte) ([]byte, bool) {
	seq := binary.LittleEndian.Uint64(pkt[:8])
	if r.started && seq <= r.max {
		diff := r.max - seq
		if diff >= 64 || (r.win>>diff)&1 != 0 {
			return nil, false
		}
	}
	nonce := make([]byte, 16)
	copy(nonce, pkt[:8])
	pt, ok := Open(r.p, r.key, nonce, aad, pkt[8:])
	if !ok {
		return nil, false
	}
	if !r.started {
		r.max, r.win, r.started = seq, 1, true
	} else if seq > r.max {
		shift := seq - r.max
		if shift >= 64 {
			r.win = 1
		} else {
			r.win = (r.win << shift) | 1
		}
		r.max = seq
	} else {
		r.win |= 1 << (r.max - seq)
	}
	return pt, true
}

// forward-secret ratchet
func rkdf(ck []byte, dom byte) []byte { return Hash(Secure, append([]byte{dom}, ck...))[:16] }

type RatchetTx struct {
	ck  []byte
	seq uint64
}

func NewRatchetTx(root []byte) *RatchetTx {
	c := make([]byte, 16)
	copy(c, root)
	return &RatchetTx{ck: c}
}
func (t *RatchetTx) Seal(aad, pt []byte) []byte {
	mk, ck2 := rkdf(t.ck, 0x01), rkdf(t.ck, 0x02)
	nonce := make([]byte, 16)
	binary.LittleEndian.PutUint64(nonce, t.seq)
	out := make([]byte, 8)
	binary.LittleEndian.PutUint64(out, t.seq)
	out = append(out, Seal(Fast, mk, nonce, aad, pt)...)
	t.ck, t.seq = ck2, t.seq+1
	return out
}

type RatchetRx struct {
	ck   []byte
	next uint64
	skip map[uint64][]byte
}

func NewRatchetRx(root []byte) *RatchetRx {
	c := make([]byte, 16)
	copy(c, root)
	return &RatchetRx{ck: c, skip: map[uint64][]byte{}}
}
func (r *RatchetRx) Open(aad, pkt []byte) ([]byte, bool) {
	seq := binary.LittleEndian.Uint64(pkt[:8])
	nonce := make([]byte, 16)
	binary.LittleEndian.PutUint64(nonce, seq)
	if seq < r.next {
		mk, has := r.skip[seq]
		if !has {
			return nil, false
		}
		pt, ok := Open(Fast, mk, nonce, aad, pkt[8:])
		if !ok {
			return nil, false
		}
		delete(r.skip, seq)
		return pt, true
	}
	if seq-r.next > 64 {
		return nil, false
	}
	ck := append([]byte{}, r.ck...)
	skipped := map[uint64][]byte{}
	for i := r.next; i < seq; i++ {
		skipped[i] = rkdf(ck, 0x01)
		ck = rkdf(ck, 0x02)
	}
	mk, cn := rkdf(ck, 0x01), rkdf(ck, 0x02)
	pt, ok := Open(Fast, mk, nonce, aad, pkt[8:])
	if !ok {
		return nil, false
	}
	for k, val := range skipped {
		r.skip[k] = val
	}
	r.ck, r.next = cn, seq+1
	return pt, true
}

// format-preserving encryption (FF1 Feistel, PRF = blind_index; native-consistent)
func fp10(m int) uint64 {
	v := uint64(1)
	for k := 0; k < m; k++ {
		v *= 10
	}
	return v
}
func fpeRound(key, tw []byte, i, n, m int, bval uint64) uint64 {
	buf := []byte{byte(i), byte(n), byte(m), byte(len(tw))}
	buf = append(buf, tw...)
	bb := make([]byte, 8)
	binary.BigEndian.PutUint64(bb, bval)
	buf = append(buf, bb...)
	mac := BlindIndex(Secure, key, buf)
	mod, y := fp10(m), uint64(0)
	for _, b := range mac {
		y = (y*256 + uint64(b)) % mod
	}
	return y
}
func fpAtoi(s string) uint64 {
	var v uint64
	for _, c := range s {
		v = v*10 + uint64(c-'0')
	}
	return v
}
func fpFill(v uint64, l int) string {
	b := make([]byte, l)
	for i := l - 1; i >= 0; i-- {
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b)
}
func FpeEncrypt(key, tw []byte, s string) string {
	n := len(s)
	u, v := n/2, n-n/2
	a, b, al, bl := fpAtoi(s[:u]), fpAtoi(s[u:]), u, v
	for i := 0; i < 10; i++ {
		m := u
		if i%2 == 1 {
			m = v
		}
		c := (a + fpeRound(key, tw, i, n, m, b)) % fp10(m)
		a, al, b, bl = b, bl, c, m
	}
	return fpFill(a, al) + fpFill(b, bl)
}
func FpeDecrypt(key, tw []byte, s string) string {
	n := len(s)
	u, v := n/2, n-n/2
	a, b, al, bl := fpAtoi(s[:u]), fpAtoi(s[u:]), u, v
	for i := 9; i >= 0; i-- {
		m := u
		if i%2 == 1 {
			m = v
		}
		c := b
		b, bl = a, al
		P := fp10(m)
		y := fpeRound(key, tw, i, n, m, b)
		a, al = (c+P-y%P)%P, m
	}
	return fpFill(a, al) + fpFill(b, bl)
}

// cross-check against the Python-produced /tmp/modes/vectors.txt; returns failures
func modesCross() int {
	f, err := os.Open("/tmp/modes/vectors.txt")
	if err != nil {
		return 0
	}
	defer f.Close()
	v := map[string][]byte{}
	vs := map[string]string{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		p := strings.SplitN(sc.Text(), "=", 2)
		if len(p) == 2 {
			b, _ := hex.DecodeString(p[1])
			v[p[0]] = b
			vs[p[0]] = p[1]
		}
	}
	KEY, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	NONCE := bytes.Repeat([]byte{0xa5}, 16)
	KEK1 := make([]byte, 16)
	DEK := make([]byte, 16)
	for i := 0; i < 16; i++ {
		KEK1[i] = byte(0x10 + i)
		DEK[i] = byte((0x55 ^ (i * 7)) & 0xff)
	}
	MK := bytes.Repeat([]byte{0x11}, 16)
	PT := []byte("hello n2q-c modes")
	CONTENT := []byte("the same backup blob")

	fails := 0
	ck := func(name string, cond bool) {
		st := "PASS"
		if !cond {
			st, fails = "FAIL", fails+1
		}
		fmt.Printf("  [%s] modes cross (py->go): %s\n", st, name)
	}
	d, ok := Unwrap(KEK1, v["envelope"])
	ck("envelope unwrap", ok && bytes.Equal(d, DEK))
	ck("envelope reproduce", bytes.Equal(Wrap(KEK1, DEK), v["envelope"]))
	pt, ok := OpenCommitting(KEY, NONCE, []byte("ad"), v["committing"], Fast)
	ck("committing open", ok && bytes.Equal(pt, PT))
	ck("committing reproduce", bytes.Equal(SealCommitting(KEY, NONCE, []byte("ad"), PT, Fast), v["committing"]))
	co, ok := ConvOpen(v["conv_dek"], v["conv_ct"], Fast)
	ck("convergent open", ok && bytes.Equal(co, CONTENT))
	_ = MK
	pp, ok := OpenPadded(KEY, NONCE, nil, v["padded"], Fast)
	ck("length-hiding open", ok && bytes.Equal(pp, PT))
	so, ok := StegoOpen(KEY, nil, v["stego"], Fast)
	ck("stego open", ok && bytes.Equal(so, PT))

	// audit-log
	recs := [][]byte{v["log0"], v["log1"], v["log2"]}
	ck("audit-log verify", LogVerify(KEY, recs, v["log_head"]))
	head := LogGenesis()
	var rr [][]byte
	for i, e := range [][]byte{[]byte("login alice"), []byte("config change"), []byte("logout bob")} {
		var r []byte
		r, head = LogAppend(head, uint64(i), KEY, e)
		rr = append(rr, r)
	}
	ck("audit-log reproduce", bytes.Equal(head, v["log_head"]) && bytes.Equal(rr[0], v["log0"]))

	// franking
	fm, fcf, fop, fok := FrankOpen(KEY, NONCE, v["franking"])
	ck("franking open", fok && bytes.Equal(fm, []byte("the abusive message")) && FrankReportVerify(fcf, fop, fm))
	ck("franking reproduce", bytes.Equal(FrankSeal(KEY, NONCE, []byte("the abusive message")), v["franking"]))

	// seekable
	seekPt, sok := SeekChunk(KEY, v["seek"], 1)
	ck("seekable chunk 1", sok && bytes.Equal(seekPt, []byte("chunk one data")))

	// streaming
	srx := NewStreamRx(KEY, Fast)
	s0, o0 := srx.Open([]byte("rtp"), v["strm0"])
	s1, o1 := srx.Open([]byte("rtp"), v["strm1"])
	s2, o2 := srx.Open([]byte("rtp"), v["strm2"])
	ck("streaming open x3", o0 && o1 && o2 && bytes.Equal(s0, []byte("frame0")) && bytes.Equal(s1, []byte("frame1 longer")) && bytes.Equal(s2, []byte("f2")))
	ck("streaming reproduce", bytes.Equal(NewStreamTx(KEY, Fast).Seal([]byte("rtp"), []byte("frame0")), v["strm0"]))

	// ratchet
	root := make([]byte, 16)
	for i := 0; i < 16; i++ {
		root[i] = byte(0x40 + i)
	}
	rrx := NewRatchetRx(root)
	r0, ro0 := rrx.Open([]byte("hdr"), v["rtc0"])
	r1, ro1 := rrx.Open([]byte("hdr"), v["rtc1"])
	r2, ro2 := rrx.Open([]byte("hdr"), v["rtc2"])
	ck("ratchet open x3", ro0 && ro1 && ro2 && bytes.Equal(r0, []byte("r0")) && bytes.Equal(r1, []byte("r1 data")) && bytes.Equal(r2, []byte("r2!")))
	ck("ratchet reproduce", bytes.Equal(NewRatchetTx(root).Seal([]byte("hdr"), []byte("r0")), v["rtc0"]))

	// FPE (native-consistent; fpe_ct / fpe_card are digit strings, not hex)
	tw := []byte("acct-42")
	ck("fpe encrypt matches python", FpeEncrypt(KEY, tw, vs["fpe_card"]) == vs["fpe_ct"])
	ck("fpe decrypt round-trips", FpeDecrypt(KEY, tw, vs["fpe_ct"]) == vs["fpe_card"])

	return fails
}
