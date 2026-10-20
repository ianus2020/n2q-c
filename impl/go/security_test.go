package main

import (
	"bytes"
	"testing"
)

func TestSecurity(t *testing.T) {
	key := make([]byte, 16)
	nonce := make([]byte, 16)
	for _, profile := range []int{0, 12, -1, 17} {
		if Seal(profile, key, nonce, nil, []byte("secret")) != nil {
			t.Fatal("profile")
		}
	}
	for _, bad := range []string{"", "n", "nqc.", "xxxxAAAA"} {
		if _, ok := OpenToken(key, nil, bad); ok {
			t.Fatal("frame")
		}
	}
	tok := SealToken(Secure, key, nonce, nil, []byte("secret"))
	if _, ok := OpenToken(key, nil, tok+"\n"); ok {
		t.Fatal("canonical frame")
	}
	for _, profile := range []int{Secure, Fast} {
		a, e := writeContainer(profile, key, [][]byte{[]byte("first"), []byte("second")})
		if e != nil {
			t.Fatal(e)
		}
		b, _ := writeContainer(profile, key, [][]byte{[]byte("other"), []byte("second")})
		for _, bad := range [][]byte{a[:22], a[:48], a[:len(a)-1], append(append([]byte{}, a[:48]...), b[48:]...)} {
			if _, e := readContainer(key, bad); e == nil {
				t.Fatal("file auth")
			}
		}
		pt, e := readContainer(key, a)
		if e != nil || !bytes.Equal(pt[1], []byte("second")) {
			t.Fatal("roundtrip")
		}
		if _, ok := SeekChunk(key, a[:23], 0); ok {
			t.Fatal("seek bounds")
		}
	}
	r := NewStreamRx(key, Secure)
	if _, ok := r.Open(nil, []byte{}); ok {
		t.Fatal("short packet")
	}
}
func TestInvalidFPE(t *testing.T) {
	for _, s := range []string{"", "1", "жж", "1a", "1234567890123456789"} {
		if FpeEncrypt(make([]byte, 16), nil, s) != "" || FpeDecrypt(make([]byte, 16), nil, s) != "" {
			t.Fatal("invalid FPE")
		}
	}
}
