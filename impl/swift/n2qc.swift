// N2Q reference implementation (Swift) — N2Q-128 suite (QP-320).
//
// Faithful port of the verified Rust/C/Go/Python references, with a built-in
// self-test against the published KATs: run `swift n2qc.swift` and it prints
// PASS/FAIL. (Written to spec but not compiled in the authoring session — the
// self-test is how you verify it before any use.)
//

// Audit status: see STATUS.md in the repository root.
import Foundation

let SBOX: [UInt8] = [
    0x1b,0x04,0x0d,0x06,0x1f,0x1c,0x10,0x0e,0x03,0x15,0x17,0x13,0x14,0x0f,0x0b,0x11,
    0x01,0x08,0x05,0x19,0x18,0x16,0x00,0x0a,0x0c,0x1e,0x02,0x07,0x1a,0x12,0x1d,0x09]
let ROTS: [(UInt64, UInt64)] = [(38,55),(1,23),(23,36),(16,14),(20,46)]
let RC: [UInt64] = [0x15,0xe3,0x2d,0xa2,0x5e,0x5c,0xab,0xae,0xc8,0x9b,0xb6,0xb3,0xeb,0xbf,0xd9,0xf2]

let SECURE = 16, FAST = 8, B = 8
let DOM_HASH: UInt64 = 1, DOM_MAC: UInt64 = 2, DOM_ENC: UInt64 = 3, DOM_BI: UInt64 = 4

func rotr(_ x: UInt64, _ r: UInt64) -> UInt64 { (x >> r) | (x << (64 - r)) }

func permute(_ input: [UInt64], _ rounds: Int) -> [UInt64] {
    var s = input
    for i in 0..<rounds {
        s[2] ^= RC[i]                               // pC
        var out = [UInt64](repeating: 0, count: 5)  // pS
        for j in 0..<64 {
            let jj = UInt64(j)
            let col = Int((s[0] >> jj) & 1)
                | (Int((s[1] >> jj) & 1) << 1)
                | (Int((s[2] >> jj) & 1) << 2)
                | (Int((s[3] >> jj) & 1) << 3)
                | (Int((s[4] >> jj) & 1) << 4)
            let o = SBOX[col]
            for k in 0..<5 { out[k] |= UInt64((o >> k) & 1) << jj }
        }
        s = out
        for k in 0..<5 { s[k] ^= rotr(s[k], ROTS[k].0) ^ rotr(s[k], ROTS[k].1) }   // pL
    }
    return s
}

func le64(_ b: ArraySlice<UInt8>) -> UInt64 {
    var v: UInt64 = 0
    for (i, byte) in b.enumerated() { v |= UInt64(byte) << (8 * i) }
    return v
}
func put64(_ x: UInt64) -> [UInt8] { (0..<8).map { UInt8((x >> (8 * $0)) & 0xff) } }

func pad(_ msg: [UInt8]) -> [UInt8] {
    var m = msg; m.append(0x01)
    while m.count % B != 0 { m.append(0) }
    m[m.count - 1] |= 0x80
    return m
}
func absorb(_ st: [UInt64], _ msg: [UInt8], _ r: Int) -> [UInt64] {
    var s = st; let p = pad(msg)
    var o = 0
    while o < p.count { s[0] ^= le64(p[o..<o+B]); s = permute(s, r); o += B }
    return s
}
func squeeze(_ st: [UInt64], _ n: Int, _ r: Int) -> [UInt8] {
    var s = st; var out = [UInt8]()
    while out.count < n { out += put64(s[0]); s = permute(s, r) }
    return Array(out[0..<n])
}

func hashN2Q(_ r: Int, _ msg: [UInt8]) -> [UInt8] {
    var s = [UInt64](repeating: 0, count: 5); s[4] ^= DOM_HASH; s = permute(s, r)
    return squeeze(absorb(s, msg, r), 32, r)
}
func mac(_ r: Int, _ key: [UInt8], _ data: [UInt8], _ dom: UInt64) -> [UInt8] {
    var s = [UInt64](repeating: 0, count: 5)
    s[1] = le64(key[0..<8]); s[2] = le64(key[8..<16]); s[4] ^= dom; s = permute(s, r)
    return squeeze(absorb(s, data, r), 16, r)
}
func keystream(_ r: Int, _ key: [UInt8], _ v: [UInt8], _ n: Int) -> [UInt8] {
    var s = [UInt64](repeating: 0, count: 5)
    s[1] = le64(key[0..<8]); s[2] = le64(key[8..<16])
    s[3] = le64(v[0..<8]); s[4] = le64(v[8..<16]) ^ DOM_ENC; s = permute(s, r)
    return squeeze(s, n, r)
}
func sivInput(_ nonce: [UInt8], _ ad: [UInt8], _ pt: [UInt8]) -> [UInt8] {
    nonce + put64(UInt64(ad.count)) + ad + put64(UInt64(pt.count)) + pt
}
func seal(_ profile: Int, _ key: [UInt8], _ nonce: [UInt8], _ ad: [UInt8], _ pt: [UInt8]) -> [UInt8] {
    let v = mac(profile, key, sivInput(nonce, ad, pt), DOM_MAC)
    let ks = keystream(profile, key, v, pt.count)
    return v + zip(pt, ks).map { $0 ^ $1 }
}
func openN2Q(_ profile: Int, _ key: [UInt8], _ nonce: [UInt8], _ ad: [UInt8], _ sealed: [UInt8]) -> [UInt8]? {
    if sealed.count < 16 { return nil }
    let v = Array(sealed[0..<16]); let ct = Array(sealed[16...])
    let ks = keystream(profile, key, v, ct.count)
    let pt = zip(ct, ks).map { $0 ^ $1 }
    return ctEq(v, mac(profile, key, sivInput(nonce, ad, pt), DOM_MAC)) ? pt : nil
}
func blindIndex(_ profile: Int, _ key: [UInt8], _ value: [UInt8]) -> [UInt8] { mac(profile, key, value, DOM_BI) }
func ctEq(_ a: [UInt8], _ b: [UInt8]) -> Bool {
    if a.count != b.count { return false }
    var acc: UInt8 = 0; for i in 0..<a.count { acc |= a[i] ^ b[i] }; return acc == 0
}
func sealToken(_ profile: Int, _ key: [UInt8], _ nonce: [UInt8], _ ad: [UInt8], _ pt: [UInt8]) -> String {
    let suite: UInt8 = 0x01 | (profile == FAST ? 0x20 : 0)
    let raw = [1, suite] + nonce + seal(profile, key, nonce, ad, pt)
    let b64 = Data(raw).base64EncodedString().replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    return "nqc." + b64
}
func openToken(_ key: [UInt8], _ ad: [UInt8], _ token: String) -> [UInt8]? {
    var b = String(token.dropFirst(4)).replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    while b.count % 4 != 0 { b += "=" }
    guard let d = Data(base64Encoded: b) else { return nil }
    let raw = [UInt8](d); if raw.count < 18 { return nil }
    let profile = (raw[1] & 0x20) != 0 ? FAST : SECURE
    return openN2Q(profile, key, Array(raw[2..<18]), ad, Array(raw[18...]))
}

// ---- N2QF binary file container (N2Q-128): "N2QF"|ver|suite|{le32|sealed}* ----
func encryptFile(_ profile: Int, _ key: [UInt8], _ inPath: String, _ outPath: String) throws {
    let data = try Data(contentsOf: URL(fileURLWithPath: inPath))
    let suite: UInt8 = 0x01 | (profile == FAST ? 0x20 : 0)          // 128-bit suite
    var out = Data([0x4e, 0x32, 0x51, 0x46, 1, suite])              // "N2QF" | ver | suite
    var idx: UInt64 = 0, off = 0
    while off < data.count {
        let end = min(off + 65536, data.count)
        var nonce = [UInt8](repeating: 0, count: 16)
        withUnsafeBytes(of: idx.littleEndian) { nonce.replaceSubrange(0..<8, with: $0) }
        let sealed = seal(profile, key, nonce, [], [UInt8](data[off..<end]))  // raw tag||ct
        var l = UInt32(sealed.count).littleEndian
        out.append(Data(bytes: &l, count: 4))
        out.append(Data(sealed))
        idx += 1; off = end
    }
    try out.write(to: URL(fileURLWithPath: outPath))
}
func decryptFile(_ key: [UInt8], _ inPath: String, _ outPath: String) throws {
    let data = [UInt8](try Data(contentsOf: URL(fileURLWithPath: inPath)))
    guard data.count >= 6, Array(data[0..<4]) == [0x4e, 0x32, 0x51, 0x46] else {
        throw NSError(domain: "N2Q", code: 1)   // not an N2QF file
    }
    let profile = (data[5] & 0x20) != 0 ? FAST : SECURE
    var out = Data(), p = 6, idx: UInt64 = 0
    while p < data.count {
        let len = data[p..<p+4].enumerated().reduce(UInt32(0)) { $0 | UInt32($1.1) << (8 * $1.0) }
        p += 4
        let sealed = Array(data[p..<p+Int(len)]); p += Int(len)
        var nonce = [UInt8](repeating: 0, count: 16)
        withUnsafeBytes(of: idx.littleEndian) { nonce.replaceSubrange(0..<8, with: $0) }
        guard let pt = openN2Q(profile, key, nonce, [], sealed) else {
            throw NSError(domain: "N2Q", code: 2)   // authentication failed
        }
        out.append(Data(pt)); idx += 1
    }
    try out.write(to: URL(fileURLWithPath: outPath))
}

// ---- self-test ----
func hx(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }
var fails = 0
func check(_ name: String, _ got: String, _ exp: String) {
    let ok = got == exp; if !ok { fails += 1 }
    print("  [\(ok ? "PASS" : "FAIL")] \(name)")
    if !ok { print("     got \(got)\n     exp \(exp)") }
}
let key = [UInt8](Data(base64Encoded: "ABEiM0RVZneImaq7zN3u/w==")!)  // 00112233...eeff
let nonce = [UInt8](repeating: 0xa5, count: 16)

// CLI file mode:  swift n2qc.swift encrypt|decrypt <in> <out>   (fixed demo key)
if CommandLine.arguments.count == 4,
   CommandLine.arguments[1] == "encrypt" || CommandLine.arguments[1] == "decrypt" {
    let a = CommandLine.arguments
    do {
        if a[1] == "encrypt" { try encryptFile(FAST, key, a[2], a[3]) }
        else { try decryptFile(key, a[2], a[3]) }
    } catch { print("error:", error); exit(1) }
    exit(0)
}

print("N2Q Swift reference — KAT cross-check")
let s = permute([0,0,0,0,0], 12)
check("QP-320 zero p^12", String(format: "%016llx %016llx", s[0], s[1]), "6c3d34cc09474fbb 4ad0c1e3cc099b31")
check("hash(\"\") Secure", hx(hashN2Q(SECURE, [UInt8]("".utf8))), "5349a47ebb78bb4a403a518a28f86740ddfd96a880f72ea6ada15a1656072bed")
check("seal Secure", hx(seal(SECURE, key, nonce, [UInt8]("header".utf8), [UInt8]("hello n2q-c".utf8))), "44c28948f18c37050af8cc5ece767a954c74546878cf40b5053c57")
check("seal Fast", hx(seal(FAST, key, nonce, [UInt8]("header".utf8), [UInt8]("hello n2q-c".utf8))), "e0328e3fdecb1cfe6cc102e8fec37933606966d993cdecf8f20ea0")
check("blind_index", hx(blindIndex(SECURE, key, [UInt8]("alice@x.com".utf8))), "15b058f9a3b1f5935899d03ac71ba415")
let tok = sealToken(FAST, key, nonce, [UInt8]("ad".utf8), [UInt8]("the quick brown fox".utf8))
check("token Fast roundtrip", String(bytes: openToken(key, [UInt8]("ad".utf8), tok) ?? [], encoding: .utf8) ?? "", "the quick brown fox")
print(fails == 0 ? "ALL PASS" : "\(fails) FAILURES")
