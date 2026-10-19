// N2Q reference implementation (Swift) — N2Q-128 suite (QP-320).
//
// Faithful port of the verified Rust/C/Go/Python references, with a built-in
// self-test against the published KATs: run `swift n2qc.swift` and it prints
// PASS/FAIL. (Written to spec but not compiled in the authoring session — the
// self-test is how you verify it before any use.)
//

// Audit status: see STATUS.md in the repository root.
import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

let SBOX: [UInt8] = [
    0x1b,0x04,0x0d,0x06,0x1f,0x1c,0x10,0x0e,0x03,0x15,0x17,0x13,0x14,0x0f,0x0b,0x11,
    0x01,0x08,0x05,0x19,0x18,0x16,0x00,0x0a,0x0c,0x1e,0x02,0x07,0x1a,0x12,0x1d,0x09]
let ROTS: [(UInt64, UInt64)] = [(38,55),(1,23),(23,36),(16,14),(20,46)]
let RC: [UInt64] = [0x15,0xe3,0x2d,0xa2,0x5e,0x5c,0xab,0xae,0xc8,0x9b,0xb6,0xb3,0xeb,0xbf,0xd9,0xf2]

let SECURE = 16, FAST = 8, B = 8
let DOM_HASH: UInt64 = 1, DOM_MAC: UInt64 = 2, DOM_ENC: UInt64 = 3, DOM_BI: UInt64 = 4

let ANF: [[Int]] = (0..<5).map { k in
    var a = SBOX.map { Int(($0 >> k) & 1) }
    for bit in [1,2,4,8,16] { for m in 0..<32 where m & bit != 0 { a[m] ^= a[m ^ bit] } }
    return (0..<32).filter { a[$0] != 0 }
}
func valid(_ r: Int, _ key: [UInt8]) -> Bool { (r == SECURE || r == FAST) && key.count == 16 }
func rotr(_ x: UInt64, _ r: UInt64) -> UInt64 { (x >> r) | (x << (64 - r)) }

func permute(_ input: [UInt64], _ rounds: Int) -> [UInt64] {
    var s = input
    for i in 0..<rounds {
        s[2] ^= RC[i]                               // pC
        var out = [UInt64](repeating: 0, count: 5)  // pS
        for k in 0..<5 { for m in ANF[k] {
            var term = UInt64.max
            for lane in 0..<5 where m & (1 << lane) != 0 { term &= s[lane] }
            out[k] ^= term
        } }
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
    guard r == SECURE || r == FAST else { return [] }
    var s = [UInt64](repeating: 0, count: 5); s[4] ^= DOM_HASH; s = permute(s, r)
    return squeeze(absorb(s, msg, r), 32, r)
}
func mac(_ r: Int, _ key: [UInt8], _ data: [UInt8], _ dom: UInt64) -> [UInt8] {
    guard valid(r,key) else { return [] }
    var s = [UInt64](repeating: 0, count: 5)
    s[1] = le64(key[0..<8]); s[2] = le64(key[8..<16]); s[4] ^= dom; s = permute(s, r)
    return squeeze(absorb(s, data, r), 16, r)
}
func keystream(_ r: Int, _ key: [UInt8], _ v: [UInt8], _ n: Int) -> [UInt8] {
    guard valid(r,key), v.count == 16, n >= 0 else { return [] }
    var s = [UInt64](repeating: 0, count: 5)
    s[1] = le64(key[0..<8]); s[2] = le64(key[8..<16])
    s[3] = le64(v[0..<8]); s[4] = le64(v[8..<16]) ^ DOM_ENC; s = permute(s, r)
    return squeeze(s, n, r)
}
func sivInput(_ nonce: [UInt8], _ ad: [UInt8], _ pt: [UInt8]) -> [UInt8] {
    nonce + put64(UInt64(ad.count)) + ad + put64(UInt64(pt.count)) + pt
}
func seal(_ profile: Int, _ key: [UInt8], _ nonce: [UInt8], _ ad: [UInt8], _ pt: [UInt8]) -> [UInt8] {
    guard valid(profile,key), nonce.count == 16 else { return [] }
    let v = mac(profile, key, sivInput(nonce, ad, pt), DOM_MAC)
    let ks = keystream(profile, key, v, pt.count)
    return v + zip(pt, ks).map { $0 ^ $1 }
}
func openN2Q(_ profile: Int, _ key: [UInt8], _ nonce: [UInt8], _ ad: [UInt8], _ sealed: [UInt8]) -> [UInt8]? {
    guard valid(profile,key), nonce.count == 16 else { return nil }
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
    guard valid(profile,key), nonce.count == 16 else { return "" }
    let suite: UInt8 = 0x01 | (profile == FAST ? 0x20 : 0)
    let raw = [1, suite] + nonce + seal(profile, key, nonce, ad, pt)
    let b64 = Data(raw).base64EncodedString().replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    return "nqc." + b64
}
func openToken(_ key: [UInt8], _ ad: [UInt8], _ token: String) -> [UInt8]? {
    guard token.utf8.count <= 24*1024*1024, token.hasPrefix("nqc.") else { return nil }
    let body = String(token.dropFirst(4))
    guard body.utf8.allSatisfy({ (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 45 || $0 == 95 }) else { return nil }
    var b = String(token.dropFirst(4)).replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    while b.count % 4 != 0 { b += "=" }
    guard let d = Data(base64Encoded: b) else { return nil }
    let raw = [UInt8](d)
    let canonical = d.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    guard canonical == body, raw.count >= 34, raw[0] == 1, [UInt8(1), 0x21].contains(raw[1]) else { return nil }
    let profile = (raw[1] & 0x20) != 0 ? FAST : SECURE
    return openN2Q(profile, key, Array(raw[2..<18]), ad, Array(raw[18...]))
}

// N2QF v2. Bounded records and mandatory authenticated final record.
func fileError() -> NSError { NSError(domain: "N2QF v2 authentication/format", code: 1) }
func fileAD(_ header: [UInt8], _ kind: UInt8, _ idx: UInt64, _ total: UInt64) -> [UInt8] {
    Array("N2QF/v2".utf8) + header + [kind] + put64(idx) + put64(total)
}
func readUpTo(_ input: FileHandle, _ size: Int) throws -> [UInt8] {
    var data = Data()
    while data.count < size {
        guard let part = try input.read(upToCount: size-data.count), !part.isEmpty else { break }
        data.append(part)
    }
    return [UInt8](data)
}
func readExact(_ input: FileHandle, _ size: Int) throws -> [UInt8] {
    let data = try readUpTo(input,size)
    guard data.count == size else { throw fileError() }
    return data
}
// The closure receives a private 0600 staging file. Publication happens only
// after it completes; failed/truncated authentication leaves the destination intact.
func atomicFile(_ path: String, _ write: (FileHandle) throws -> Void) throws {
    var template = Array((path + ".n2q-XXXXXX").utf8CString)
    let fd = mkstemp(&template)
    guard fd >= 0 else { throw fileError() }
    let name = String(cString: template), handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
    defer { try? handle.close(); unlink(name) }
    try write(handle); try handle.synchronize(); try handle.close()
    guard rename(name,path) == 0 else { throw fileError() }
}
func encryptFile(_ profile: Int, _ key: [UInt8], _ inPath: String, _ outPath: String) throws {
    guard valid(profile,key) else { throw fileError() }
    let input = try FileHandle(forReadingFrom: URL(fileURLWithPath: inPath))
    defer { try? input.close() }
    try atomicFile(outPath) { output in
        var rng = SystemRandomNumberGenerator()
        let hdr = Array("N2QF".utf8) + [2, UInt8(profile == FAST ? 0x21 : 1)] + (0..<16).map { _ in UInt8.random(in: 0...255, using: &rng) }
        try output.write(contentsOf: Data(hdr))
        var idx: UInt64 = 0, total: UInt64 = 0
        while true {
            let pt = try readUpTo(input,65536), kind: UInt8 = pt.isEmpty ? 1 : 0
            let sealed = seal(profile,key,put64(idx) + [UInt8](repeating: 0,count: 8),fileAD(hdr,kind,idx,total),pt)
            let record = [kind] + Array(put64(UInt64(sealed.count)).prefix(4)) + sealed
            try output.write(contentsOf: Data(record))
            if kind == 1 { break }
            let (next,overflow) = total.addingReportingOverflow(UInt64(pt.count))
            guard !overflow, idx < UInt64.max else { throw fileError() }
            total=next;idx+=1
        }
    }
}
func decryptFile(_ key: [UInt8], _ inPath: String, _ outPath: String) throws {
    guard key.count == 16 else { throw fileError() }
    let input = try FileHandle(forReadingFrom: URL(fileURLWithPath: inPath))
    defer { try? input.close() }
    try atomicFile(outPath) { output in
        let hdr = try readExact(input,22)
        guard Array(hdr.prefix(5)) == Array("N2QF".utf8)+[2], [UInt8(1),0x21].contains(hdr[5]) else { throw fileError() }
        let profile = hdr[5] == 0x21 ? FAST : SECURE
        var idx: UInt64 = 0, total: UInt64 = 0
        while true {
            let rec = try readExact(input,5), kind=rec[0], len=Int(le64(rec[1..<5]))
            guard ((kind == 0 && len > 16 && len <= 65552) || (kind == 1 && len == 16)) else { throw fileError() }
            let sealed = try readExact(input,len)
            guard let pt = openN2Q(profile,key,put64(idx)+[UInt8](repeating: 0,count: 8),fileAD(hdr,kind,idx,total),sealed) else { throw fileError() }
            if kind == 1 { guard try readUpTo(input,1).isEmpty else { throw fileError() }; break }
            let (next,overflow) = total.addingReportingOverflow(UInt64(pt.count))
            guard !overflow, idx < UInt64.max else { throw fileError() }
            total=next;idx+=1
            try output.write(contentsOf: Data(pt))
        }
    }
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

// CLI: explicit 16-byte binary key file, Secure profile.
if CommandLine.arguments.count > 1 {
    let a = CommandLine.arguments
    guard a.count == 5, a[1] == "encrypt" || a[1] == "decrypt" else {
        print("usage: n2qc encrypt|decrypt KEYFILE INPUT OUTPUT"); exit(1)
    }
    do {
        let k = [UInt8](try Data(contentsOf: URL(fileURLWithPath: a[2])))
        guard k.count == 16 else { throw fileError() }
        if a[1] == "encrypt" { try encryptFile(SECURE,k,a[3],a[4]) }
        else { try decryptFile(k,a[3],a[4]) }
    } catch { print("error:",error); exit(1) }
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

exit(fails == 0 ? 0 : 1)
