// N2Q reference implementation (Go) — N2Q-128 suite (QP-320).
//
// Byte-exact with the Rust, C, and Python references (see the self-test in
// main()). The N2Q-256 suite (QP-640) follows the identical structure over a
// Audit status: see STATUS.md in the repository root.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"os"
	"path/filepath"
	"strings"
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

func valid(profile int, key []byte, size int) bool {
	return (profile == Secure || profile == Fast) && len(key) == size
}

// Public Möbius transform, never indexed by secret state.
var anf = func() [5][]int {
	var out [5][]int
	for k := 0; k < 5; k++ {
		var a [32]byte
		for m := 0; m < 32; m++ {
			a[m] = (sbox[m] >> k) & 1
		}
		for bit := 1; bit < 32; bit <<= 1 {
			for m := 0; m < 32; m++ {
				if m&bit != 0 {
					a[m] ^= a[m^bit]
				}
			}
		}
		for m := 0; m < 32; m++ {
			if a[m] != 0 {
				out[k] = append(out[k], m)
			}
		}
	}
	return out
}()

func rotr(x uint64, r uint) uint64 { return bits.RotateLeft64(x, -int(r)) }

// permute applies `rounds` rounds of QP-320 to the 5-lane state.
func permute(s [5]uint64, rounds int) [5]uint64 {
	for i := 0; i < rounds; i++ {
		s[2] ^= uint64(rc[i]) // pC
		var out [5]uint64     // pS: 5-bit S-box per bit-column
		for k, terms := range anf {
			for _, m := range terms {
				t := ^uint64(0)
				for lane := 0; lane < 5; lane++ {
					if m&(1<<lane) != 0 {
						t &= s[lane]
					}
				}
				out[k] ^= t
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
	if r != Secure && r != Fast {
		return nil
	}
	s := [5]uint64{}
	s[4] ^= domHash
	s = permute(s, r)
	s = absorb(s, msg, r)
	return squeeze(s, 32, r)
}

func mac(r int, key, data []byte, dom byte) []byte {
	if !valid(r, key, 16) {
		return nil
	}
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
	if !valid(profile, key, 16) || len(nonce) != 16 {
		return nil
	}
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
	if !valid(profile, key, 16) || len(nonce) != 16 {
		return nil, false
	}
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
	if !valid(profile, key, 16) || len(nonce) != 16 {
		return ""
	}
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
	if len(token) > 24*1024*1024 || !strings.HasPrefix(token, "nqc.") {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(token[4:])
	if err != nil || len(raw) < 34 || raw[0] != 1 || (raw[1] != 1 && raw[1] != 0x21) || base64.RawURLEncoding.EncodeToString(raw) != token[4:] {
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
func le128(b []byte) u128 {
	return u128{binary.LittleEndian.Uint64(b[8:16]), binary.LittleEndian.Uint64(b[0:8])}
}
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
		for k, terms := range anf {
			for _, m := range terms {
				t := u128{^uint64(0), ^uint64(0)}
				for lane := 0; lane < 5; lane++ {
					if m&(1<<lane) != 0 {
						t.hi &= s[lane].hi
						t.lo &= s[lane].lo
					}
				}
				out[k] = out[k].xor(t)
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
	if r != Secure && r != Fast {
		return nil
	}
	s := [5]u128{}
	s[4] = s[4].xor(u128{0, 1}) // DOM_HASH
	s = permute640(s, r)
	return squeeze256(absorb256(s, msg, r), 64, r)
}
func mac256(r int, key, data []byte, dom byte) []byte {
	if !valid(r, key, 32) {
		return nil
	}
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
	if !valid(profile, key, 32) || len(nonce) != 16 {
		return nil
	}
	v := mac256(profile, key, sivInput(nonce, ad, pt), 2)
	ks := keystream256(profile, key, v, len(pt))
	out := append([]byte{}, v...)
	for i := range pt {
		out = append(out, pt[i]^ks[i])
	}
	return out
}
func Open256(profile int, key, nonce, ad, sealed []byte) ([]byte, bool) {
	if !valid(profile, key, 32) || len(nonce) != 16 {
		return nil, false
	}
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

// N2QF v2. See docs/n2qf.md. Writers publish only complete authenticated files.
const chunkSize = 65536

func fileAD(header []byte, kind byte, idx, total uint64) []byte {
	ad := append([]byte("N2QF/v2"), header...)
	ad = append(ad, kind)
	var x [16]byte
	binary.LittleEndian.PutUint64(x[:8], idx)
	binary.LittleEndian.PutUint64(x[8:], total)
	return append(ad, x[:]...)
}
func writeContainer(profile int, key []byte, chunks [][]byte) ([]byte, error) {
	if !valid(profile, key, len(key)) || (len(key) != 16 && len(key) != 32) {
		return nil, errors.New("invalid key/profile")
	}
	suite := byte(1)
	if len(key) == 32 {
		suite = 2
	}
	if profile == Fast {
		suite |= 0x20
	}
	header := append([]byte("N2QF"), 2, suite)
	id := make([]byte, 16)
	if _, e := rand.Read(id); e != nil {
		return nil, e
	}
	header = append(header, id...)
	out := append([]byte{}, header...)
	total := uint64(0)
	for idx := 0; idx <= len(chunks); idx++ {
		kind := byte(0)
		var pt []byte
		if idx == len(chunks) {
			kind = 1
		} else {
			pt = chunks[idx]
			if len(pt) == 0 || len(pt) > chunkSize {
				return nil, errors.New("chunk length")
			}
		}
		nonce := make([]byte, 16)
		binary.LittleEndian.PutUint64(nonce, uint64(idx))
		ad := fileAD(header, kind, uint64(idx), total)
		sealed := Seal(profile, key, nonce, ad, pt)
		if len(key) == 32 {
			sealed = Seal256(profile, key, nonce, ad, pt)
		}
		var rec [5]byte
		rec[0] = kind
		binary.LittleEndian.PutUint32(rec[1:], uint32(len(sealed)))
		out = append(out, rec[:]...)
		out = append(out, sealed...)
		total += uint64(len(pt))
	}
	return out, nil
}
func readContainer(key, data []byte) ([][]byte, error) {
	bad := errors.New("invalid or unauthenticated N2QF v2")
	if len(data) < 22 || string(data[:5]) != "N2QF\x02" {
		return nil, bad
	}
	suite := byte(1)
	if len(key) == 32 {
		suite = 2
	}
	if len(key) != 16 && len(key) != 32 {
		return nil, bad
	}
	if data[5] != suite && data[5] != (suite|0x20) {
		return nil, bad
	}
	profile := Secure
	if data[5]&0x20 != 0 {
		profile = Fast
	}
	header := data[:22]
	data = data[22:]
	var chunks [][]byte
	var idx, total uint64
	tag := len(key)
	for {
		if len(data) < 5 {
			return nil, bad
		}
		kind := data[0]
		n := uint64(binary.LittleEndian.Uint32(data[1:5]))
		data = data[5:]
		if !((kind == 0 && n > uint64(tag) && n <= uint64(chunkSize+tag)) || (kind == 1 && n == uint64(tag))) || n > uint64(len(data)) {
			return nil, bad
		}
		nonce := make([]byte, 16)
		binary.LittleEndian.PutUint64(nonce, idx)
		ad := fileAD(header, kind, idx, total)
		var pt []byte
		var ok bool
		if tag == 16 {
			pt, ok = Open(profile, key, nonce, ad, data[:int(n)])
		} else {
			pt, ok = Open256(profile, key, nonce, ad, data[:int(n)])
		}
		if !ok {
			return nil, bad
		}
		data = data[int(n):]
		if kind == 1 {
			if len(data) != 0 {
				return nil, bad
			}
			return chunks, nil
		}
		chunks = append(chunks, pt)
		idx++
		total += uint64(len(pt))
	}
}
// These helpers write only to PRIVATE staging sinks. The file APIs below
// publish after complete authentication, final-record verification and EOF.
func writeAll(w io.Writer, data []byte) error {
    for len(data)>0 {
        n,err:=w.Write(data)
        if err!=nil { return err }; if n<=0 || n>len(data) { return io.ErrShortWrite }
        data=data[n:]
    }; return nil
}
func encryptToStaging(profile int,key []byte,input io.Reader,output io.Writer) error {
    if !valid(profile,key,len(key)) || (len(key)!=16 && len(key)!=32) { return errors.New("invalid key/profile") }
    suite:=byte(1);if len(key)==32 {suite=2};if profile==Fast {suite|=0x20}
    header:=append([]byte("N2QF"),2,suite);id:=make([]byte,16)
    if _,err:=rand.Read(id);err!=nil {return err};header=append(header,id...)
    if err:=writeAll(output,header);err!=nil {return err}
    buf:=make([]byte,chunkSize);defer clear(buf)
    var idx,total uint64
    for {
        n,err:=io.ReadFull(input,buf)
        if err!=nil && err!=io.EOF && err!=io.ErrUnexpectedEOF {return err}
        kind:=byte(0);if n==0 {kind=1}
        nonce:=make([]byte,16);binary.LittleEndian.PutUint64(nonce,idx)
        ad:=fileAD(header,kind,idx,total)
        var sealed []byte
        if len(key)==16 {sealed=Seal(profile,key,nonce,ad,buf[:n])} else {sealed=Seal256(profile,key,nonce,ad,buf[:n])}
        var record [5]byte;record[0]=kind;binary.LittleEndian.PutUint32(record[1:],uint32(len(sealed)))
        if err:=writeAll(output,record[:]);err!=nil {return err}
        if err:=writeAll(output,sealed);err!=nil {return err}
        if kind==1 {return nil}
        if total>^uint64(0)-uint64(n) || idx==^uint64(0) {return errors.New("file too large")}
        total+=uint64(n);idx++
    }
}
func decryptToStaging(key []byte,input io.Reader,output io.Writer) error {
    bad:=errors.New("invalid or unauthenticated N2QF v2")
    tag:=len(key);if tag!=16 && tag!=32 {return bad}
    header:=make([]byte,22);if _,err:=io.ReadFull(input,header);err!=nil {return err}
    suite:=byte(1);if tag==32 {suite=2}
    if string(header[:5])!="N2QF\x02" || (header[5]!=suite && header[5]!=(suite|0x20)) {return bad}
    profile:=Secure;if header[5]&0x20!=0 {profile=Fast}
    sealed:=make([]byte,chunkSize+tag)
    var idx,total uint64
    for {
        var record [5]byte;if _,err:=io.ReadFull(input,record[:]);err!=nil {return err}
        kind:=record[0];n:=uint64(binary.LittleEndian.Uint32(record[1:]))
        if !((kind==0 && n>uint64(tag) && n<=uint64(chunkSize+tag)) || (kind==1 && n==uint64(tag))) {return bad}
        if _,err:=io.ReadFull(input,sealed[:int(n)]);err!=nil {return err}
        nonce:=make([]byte,16);binary.LittleEndian.PutUint64(nonce,idx)
        ad:=fileAD(header,kind,idx,total)
        var pt []byte;var ok bool
        if tag==16 {pt,ok=Open(profile,key,nonce,ad,sealed[:int(n)])} else {pt,ok=Open256(profile,key,nonce,ad,sealed[:int(n)])}
        if !ok {return bad}
        if kind==1 {
            var extra [1]byte;_,err:=io.ReadFull(input,extra[:]);if err==io.EOF {return nil}
            if err!=nil {return err};return bad
        }
        if total>^uint64(0)-uint64(len(pt)) || idx==^uint64(0) {clear(pt);return bad}
        total+=uint64(len(pt));idx++
        err:=writeAll(output,pt);clear(pt);if err!=nil {return err}
    }
}
func atomicFile(path string,write func(io.Writer) error) error {
    f,err:=os.CreateTemp(filepath.Dir(path),".n2q-*");if err!=nil {return err}
    name:=f.Name();defer os.Remove(name)
    if err=write(f);err!=nil {f.Close();return err}
    if err=f.Sync();err!=nil {f.Close();return err}
    if err=f.Close();err!=nil {return err}
    return os.Rename(name,path)
}
func EncryptFile(profile int,key []byte,inPath,outPath string) error {
    input,err:=os.Open(inPath);if err!=nil {return err};defer input.Close()
    return atomicFile(outPath,func(output io.Writer)error{return encryptToStaging(profile,key,input,output)})
}
func DecryptFile(key []byte,inPath,outPath string) error {
    input,err:=os.Open(inPath);if err!=nil {return err};defer input.Close()
    return atomicFile(outPath,func(output io.Writer)error{return decryptToStaging(key,input,output)})
}

func hx(b []byte) string {
	s := ""
	for _, x := range b {
		s += fmt.Sprintf("%02x", x)
	}
	return s
}

func main() {
	if len(os.Args) > 1 {
		if len(os.Args) != 5 || (os.Args[1] != "encrypt" && os.Args[1] != "decrypt") {
			fmt.Fprintln(os.Stderr, "usage: n2qc encrypt|decrypt KEYFILE INPUT OUTPUT")
			os.Exit(1)
		}
		key, err := os.ReadFile(os.Args[2])
		if err != nil || (len(key) != 16 && len(key) != 32) {
			fmt.Fprintln(os.Stderr, "key file must contain 16 or 32 bytes")
			os.Exit(1)
		}
		if os.Args[1] == "encrypt" {
			err = EncryptFile(Secure, key, os.Args[3], os.Args[4])
		} else {
			err = DecryptFile(key, os.Args[3], os.Args[4])
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
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

	fmt.Println("N2Q Go reference — KAT cross-check (vs Rust/C/Python)")
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
