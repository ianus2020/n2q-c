package main

import (
	"bytes"
	"testing"
)

func TestConvergentFixedBoundary(t *testing.T) {
	key := bytes.Repeat([]byte{'A'}, 16)
	for _, bad := range [][]byte{nil, key[:15], append(append([]byte(nil), key...), 'B'), make([]byte, 32)} {
		dek, ct := ConvSeal(bad, []byte("payload"), Secure)
		if dek != nil || ct != nil {
			t.Fatal("invalid master key accepted")
		}
	}
	for _, p := range []int{Secure, Fast} {
		dek, ct := ConvSeal(key, []byte("Bpayload"), p)
		expected := Hash(Secure, append(append([]byte(nil), key...), []byte("Bpayload")...))[:16]
		if !bytes.Equal(dek, expected) {
			t.Fatal("valid derivation changed")
		}
		pt, ok := ConvOpen(dek, ct, p)
		if !ok || string(pt) != "Bpayload" {
			t.Fatal("roundtrip failed")
		}
		token := SealCommitting(key, make([]byte, 16), nil, pt, p)
		for bit := 0; bit < 256; bit++ {
			bad := append([]byte(nil), token...)
			bad[bit/8] ^= 1 << uint(bit%8)
			if _, ok := OpenCommitting(key, make([]byte, 16), nil, bad, p); ok {
				t.Fatal("commitment mutation accepted")
			}
		}
	}
}
