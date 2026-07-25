<?php
/**
 * N2Q-C reference implementation (PHP 8, 64-bit) — N2Q-128 suite (QP-320).
 *
 * Faithful port of the verified Rust/C/Go/Python references. It carries a
 * built-in self-test against the published KATs: run `php n2qc.php` and it
 * prints PASS/FAIL. (This port was written to spec but not executed in the
 * authoring session — the self-test is how you verify it before any use.)
 *
 * Research artifact — NOT audited, NOT for real data.
 */

const N2Q_SBOX = [
    0x1b,0x04,0x0d,0x06,0x1f,0x1c,0x10,0x0e,0x03,0x15,0x17,0x13,0x14,0x0f,0x0b,0x11,
    0x01,0x08,0x05,0x19,0x18,0x16,0x00,0x0a,0x0c,0x1e,0x02,0x07,0x1a,0x12,0x1d,0x09,
];
const N2Q_ROTS = [[38,55],[1,23],[23,36],[16,14],[20,46]];
const N2Q_RC = [0x15,0xe3,0x2d,0xa2,0x5e,0x5c,0xab,0xae,0xc8,0x9b,0xb6,0xb3,0xeb,0xbf,0xd9,0xf2];

const N2Q_SECURE = 16, N2Q_FAST = 8, N2Q_B = 8;
const DOM_HASH=1, DOM_MAC=2, DOM_ENC=3, DOM_BI=4;

/** logical (unsigned) right shift of a 64-bit value */
function lshr(int $x, int $n): int {
    if ($n === 0) return $x;
    return ($x >> $n) & ~(-1 << (64 - $n));
}
function rotr(int $x, int $r): int {
    $r &= 63; if ($r === 0) return $x;
    return lshr($x, $r) | ($x << (64 - $r));
}
function le64(string $b): int { return unpack('P', $b)[1]; }
function put64(int $x): string { return pack('P', $x); }

function permute(array $s, int $rounds): array {
    for ($i = 0; $i < $rounds; $i++) {
        $s[2] ^= N2Q_RC[$i];                        // pC
        $out = [0,0,0,0,0];                          // pS
        for ($j = 0; $j < 64; $j++) {
            $col = (lshr($s[0],$j) & 1)
                 | ((lshr($s[1],$j) & 1) << 1)
                 | ((lshr($s[2],$j) & 1) << 2)
                 | ((lshr($s[3],$j) & 1) << 3)
                 | ((lshr($s[4],$j) & 1) << 4);
            $o = N2Q_SBOX[$col];
            for ($k = 0; $k < 5; $k++) $out[$k] |= (($o >> $k) & 1) << $j;
        }
        $s = $out;
        for ($k = 0; $k < 5; $k++)                   // pL
            $s[$k] ^= rotr($s[$k], N2Q_ROTS[$k][0]) ^ rotr($s[$k], N2Q_ROTS[$k][1]);
    }
    return $s;
}

function pad(string $m): string {
    $m .= "\x01";
    while (strlen($m) % N2Q_B) $m .= "\x00";
    $m[strlen($m)-1] = chr(ord($m[strlen($m)-1]) | 0x80);
    return $m;
}
function absorb(array $s, string $msg, int $r): array {
    $p = pad($msg);
    for ($o = 0; $o < strlen($p); $o += N2Q_B) { $s[0] ^= le64(substr($p,$o,N2Q_B)); $s = permute($s,$r); }
    return $s;
}
function squeeze(array $s, int $n, int $r): string {
    $out = '';
    while (strlen($out) < $n) { $out .= put64($s[0]); $s = permute($s,$r); }
    return substr($out, 0, $n);
}

function n2q_hash(int $r, string $msg): string {
    $s = [0,0,0,0,0]; $s[4] ^= DOM_HASH; $s = permute($s,$r);
    return squeeze(absorb($s,$msg,$r), 32, $r);
}
function n2q_mac(int $r, string $key, string $data, int $dom): string {
    $s = [0,0,0,0,0]; $s[1]=le64(substr($key,0,8)); $s[2]=le64(substr($key,8,8)); $s[4]^=$dom;
    $s = permute($s,$r);
    return squeeze(absorb($s,$data,$r), 16, $r);
}
function n2q_keystream(int $r, string $key, string $v, int $n): string {
    $s=[0,0,0,0,0]; $s[1]=le64(substr($key,0,8)); $s[2]=le64(substr($key,8,8));
    $s[3]=le64(substr($v,0,8)); $s[4]=le64(substr($v,8,8)) ^ DOM_ENC; $s=permute($s,$r);
    return squeeze($s,$n,$r);
}
function siv_input(string $nonce, string $ad, string $pt): string {
    return $nonce . pack('P',strlen($ad)) . $ad . pack('P',strlen($pt)) . $pt;
}
function n2q_seal(int $profile, string $key, string $nonce, string $ad, string $pt): string {
    $v = n2q_mac($profile,$key,siv_input($nonce,$ad,$pt),DOM_MAC);
    $ks = n2q_keystream($profile,$key,$v,strlen($pt));
    return $v . ($pt ^ substr($ks,0,strlen($pt)));
}
function n2q_open(int $profile, string $key, string $nonce, string $ad, string $sealed): ?string {
    if (strlen($sealed) < 16) return null;
    $v = substr($sealed,0,16); $ct = substr($sealed,16);
    $ks = n2q_keystream($profile,$key,$v,strlen($ct));
    $pt = $ct ^ substr($ks,0,strlen($ct));
    return hash_equals($v, n2q_mac($profile,$key,siv_input($nonce,$ad,$pt),DOM_MAC)) ? $pt : null;
}
function n2q_blind_index(int $profile, string $key, string $value): string {
    return n2q_mac($profile,$key,$value,DOM_BI);
}
function n2q_seal_token(int $profile, string $key, string $nonce, string $ad, string $pt): string {
    $suite = 0x01 | ($profile === N2Q_FAST ? 0x20 : 0);
    $raw = chr(1).chr($suite).$nonce.n2q_seal($profile,$key,$nonce,$ad,$pt);
    return 'nqc.' . rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
}
function n2q_open_token(string $key, string $ad, string $token): ?string {
    $raw = base64_decode(strtr(substr($token,4), '-_', '+/'));
    if (strlen($raw) < 18) return null;
    $profile = (ord($raw[1]) & 0x20) ? N2Q_FAST : N2Q_SECURE;
    return n2q_open($profile,$key,substr($raw,2,16),$ad,substr($raw,18));
}

// ---- N2QF binary file container (N2Q-128): "N2QF"|ver|suite|{le32|sealed}* ----
function n2q_encrypt_file(int $profile, string $key, string $in, string $out): void {
    $suite = 0x01 | ($profile === N2Q_FAST ? 0x20 : 0);        // 128-bit suite
    $fi = fopen($in, 'rb'); $fo = fopen($out, 'wb');
    fwrite($fo, "N2QF" . chr(1) . chr($suite));
    $idx = 0;
    while (($chunk = fread($fi, 65536)) !== '' && $chunk !== false) {
        $nonce  = pack('P', $idx) . str_repeat("\0", 8);       // 16-byte LE index
        $sealed = n2q_seal($profile, $key, $nonce, "", $chunk); // raw tag||ct
        fwrite($fo, pack('V', strlen($sealed)) . $sealed);     // le32 length ‖ sealed
        $idx++;
    }
    fclose($fi); fclose($fo);
}
function n2q_decrypt_file(string $key, string $in, string $out): void {
    $fi = fopen($in, 'rb'); $fo = fopen($out, 'wb');
    $hdr = fread($fi, 6);
    if (substr($hdr, 0, 4) !== "N2QF") throw new Exception("not an N2QF file");
    $profile = (ord($hdr[5]) & 0x20) ? N2Q_FAST : N2Q_SECURE;
    $idx = 0;
    while (strlen($ln = fread($fi, 4)) === 4) {
        $sealed = fread($fi, unpack('V', $ln)[1]);
        $nonce  = pack('P', $idx) . str_repeat("\0", 8);
        $pt = n2q_open($profile, $key, $nonce, "", $sealed);
        if ($pt === null) throw new Exception("authentication failed (chunk $idx)");
        fwrite($fo, $pt);
        $idx++;
    }
    fclose($fi); fclose($fo);
}

// ---- self-test (run: php n2qc.php) ----
if (PHP_SAPI === 'cli' && realpath($argv[0]) === __FILE__) {
    $fail = 0;
    $chk = function($name,$got,$exp) use (&$fail) {
        $ok = $got === $exp; if (!$ok) $fail++;
        echo "  [".($ok?'PASS':'FAIL')."] $name\n";
        if (!$ok) echo "     got $got\n     exp $exp\n";
    };
    $key = hex2bin('00112233445566778899aabbccddeeff');
    $nonce = str_repeat("\xa5", 16);
    echo "N2Q-C PHP reference — KAT cross-check\n";
    $s = permute([0,0,0,0,0], 12);
    $chk('QP-320 zero p^12', sprintf('%016x %016x', $s[0] & 0xFFFFFFFFFFFFFFFF, $s[1] & 0xFFFFFFFFFFFFFFFF),
         '6c3d34cc09474fbb 4ad0c1e3cc099b31');
    $chk('hash("") Secure', bin2hex(n2q_hash(N2Q_SECURE,'')),
         '5349a47ebb78bb4a403a518a28f86740ddfd96a880f72ea6ada15a1656072bed');
    $chk('seal Secure', bin2hex(n2q_seal(N2Q_SECURE,$key,$nonce,'header','hello n2q-c')),
         '44c28948f18c37050af8cc5ece767a954c74546878cf40b5053c57');
    $chk('seal Fast', bin2hex(n2q_seal(N2Q_FAST,$key,$nonce,'header','hello n2q-c')),
         'e0328e3fdecb1cfe6cc102e8fec37933606966d993cdecf8f20ea0');
    $chk('blind_index', bin2hex(n2q_blind_index(N2Q_SECURE,$key,'alice@x.com')),
         '15b058f9a3b1f5935899d03ac71ba415');
    $tok = n2q_seal_token(N2Q_FAST,$key,$nonce,'ad','the quick brown fox');
    $chk('token Fast roundtrip', n2q_open_token($key,'ad',$tok), 'the quick brown fox');
    echo $fail === 0 ? "ALL PASS\n" : "$fail FAILURES\n";
    exit($fail === 0 ? 0 : 1);
}
