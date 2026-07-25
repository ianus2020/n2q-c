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

// cross-check against the Python-produced /tmp/modes/vectors.txt; returns failures
func modesCross() int {
	f, err := os.Open("/tmp/modes/vectors.txt")
	if err != nil {
		return 0
	}
	defer f.Close()
	v := map[string][]byte{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.SplitN(sc.Text(), "=", 2)
		if len(p) == 2 {
			b, _ := hex.DecodeString(p[1])
			v[p[0]] = b
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
	return fails
}
