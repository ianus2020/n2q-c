<?php
// Audit status: see STATUS.md in the repository root.
/**
 * N2Q reference implementation (PHP 8, 64-bit) — N2Q-128 suite (QP-320).
 *
 * Faithful port of the verified Rust/C/Go/Python references. It carries a
 * built-in self-test against the published KATs: run `php n2qc.php` and it
 * prints PASS/FAIL. (This port was written to spec but not executed in the
 * authoring session — the self-test is how you verify it before any use.)
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

function n2q_validate(int $r, ?string $key=null, ?string $nonce=null): void {
    if (!in_array($r,[N2Q_SECURE,N2Q_FAST],true) || ($key!==null && strlen($key)!==16) || ($nonce!==null && strlen($nonce)!==16))
        throw new InvalidArgumentException('invalid profile, key or nonce');
}
function n2q_anf(): array {
    static $out=null;
    if ($out!==null) return $out;
    $out=[];
    for ($k=0;$k<5;$k++) {
        $a=[]; foreach(N2Q_SBOX as $v) $a[]=($v>>$k)&1;
        for($bit=1;$bit<32;$bit<<=1) for($m=0;$m<32;$m++) if($m&$bit) $a[$m]^=$a[$m^$bit];
        $out[$k]=[];for($m=0;$m<32;$m++) if($a[$m]) $out[$k][]=$m;
    }
    return $out;
}
function permute(array $s, int $rounds): array {
    for ($i = 0; $i < $rounds; $i++) {
        $s[2] ^= N2Q_RC[$i];                        // pC
        $out = [0,0,0,0,0];                          // pS
        foreach(n2q_anf() as $k=>$terms) foreach($terms as $m) {
            $t=-1;for($lane=0;$lane<5;$lane++) if($m&(1<<$lane)) $t&=$s[$lane];
            $out[$k]^=$t;
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
    n2q_validate($r);
    $s = [0,0,0,0,0]; $s[4] ^= DOM_HASH; $s = permute($s,$r);
    return squeeze(absorb($s,$msg,$r), 32, $r);
}
function n2q_mac(int $r, string $key, string $data, int $dom): string {
    n2q_validate($r,$key);
    $s = [0,0,0,0,0]; $s[1]=le64(substr($key,0,8)); $s[2]=le64(substr($key,8,8)); $s[4]^=$dom;
    $s = permute($s,$r);
    return squeeze(absorb($s,$data,$r), 16, $r);
}
function n2q_keystream(int $r, string $key, string $v, int $n): string {
    n2q_validate($r,$key);
    if(strlen($v)!==16 || $n<0) throw new InvalidArgumentException("invalid keystream parameters");
    $s=[0,0,0,0,0]; $s[1]=le64(substr($key,0,8)); $s[2]=le64(substr($key,8,8));
    $s[3]=le64(substr($v,0,8)); $s[4]=le64(substr($v,8,8)) ^ DOM_ENC; $s=permute($s,$r);
    return squeeze($s,$n,$r);
}
function siv_input(string $nonce, string $ad, string $pt): string {
    return $nonce . pack('P',strlen($ad)) . $ad . pack('P',strlen($pt)) . $pt;
}
function n2q_seal(int $profile, string $key, string $nonce, string $ad, string $pt): string {
    n2q_validate($profile,$key,$nonce);
    $v = n2q_mac($profile,$key,siv_input($nonce,$ad,$pt),DOM_MAC);
    $ks = n2q_keystream($profile,$key,$v,strlen($pt));
    return $v . ($pt ^ substr($ks,0,strlen($pt)));
}
function n2q_open(int $profile, string $key, string $nonce, string $ad, string $sealed): ?string {
    n2q_validate($profile,$key,$nonce);
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
    if(strlen($token)>24*1024*1024 || !preg_match('/^nqc\.[A-Za-z0-9_-]+$/D',$token)) return null;
    $body=substr($token,4); $raw=base64_decode(strtr($body,'-_','+/'),true);
    if($raw===false || strlen($raw)<34 || ord($raw[0])!==1 || !in_array(ord($raw[1]),[1,0x21],true)
        || rtrim(strtr(base64_encode($raw),'+/','-_'),'=')!==$body || strlen($key)!==16) return null;
    $profile = (ord($raw[1]) & 0x20) ? N2Q_FAST : N2Q_SECURE;
    return n2q_open($profile,$key,substr($raw,2,16),$ad,substr($raw,18));
}

// N2QF v2; whole-file validation before atomic output publication.
function n2q_file_ad(string $hdr,int $kind,int $index,int $total): string {
    return 'N2QF/v2'.$hdr.chr($kind).pack('P',$index).pack('P',$total);
}
// Bounded read, including short reads. A zero-progress non-EOF stream is an error.
function n2q_read_up_to($f,int $size): string {
    $buf='';
    while(strlen($buf)<$size) {
        $part=fread($f,$size-strlen($buf));
        if($part===false) throw new RuntimeException('read failed');
        if($part==='') {if(!feof($f)) throw new RuntimeException('read made no progress');break;}
        $buf.=$part;
    }
    return $buf;
}
function n2q_read_exact($f,int $size): string {
    $buf=n2q_read_up_to($f,$size);
    if(strlen($buf)!==$size) throw new RuntimeException('truncated file');
    return $buf;
}
function n2q_write_all($f,string $data): void {
    $offset=0;$len=strlen($data);
    while($offset<$len) {
        $n=fwrite($f,substr($data,$offset));
        if($n===false || $n===0) throw new RuntimeException('write failed');
        $offset+=$n;
    }
}
function n2q_atomic(string $path,callable $write): void {
    $parent=realpath(dirname($path));
    if($parent===false) throw new RuntimeException('output directory does not exist');
    $tmp=tempnam($parent,'.n2q-');if($tmp===false) throw new RuntimeException('temporary file failed');
    $f=null;
    try {
        if(realpath(dirname($tmp))!==$parent) throw new RuntimeException('temporary file must be in output directory');
        if(!chmod($tmp,0600)) throw new RuntimeException('file permissions');
        $f=fopen($tmp,'wb');if($f===false) throw new RuntimeException('file open');
        $write($f);
        if(!fflush($f) || (function_exists('fsync') && !fsync($f))) throw new RuntimeException('flush failed');
        if(!fclose($f)) throw new RuntimeException('close failed');$f=null;
        if(!rename($tmp,$path)) throw new RuntimeException('rename failed');
    } finally {if(is_resource($f)) fclose($f);if(file_exists($tmp)) unlink($tmp);}
}
function n2q_encrypt_file(int $profile,string $key,string $in,string $out): void {
    n2q_validate($profile,$key);
    $input=fopen($in,'rb');if($input===false) throw new RuntimeException('read open failed');
    try {
        n2q_atomic($out,function($f)use($profile,$key,$input) {
            $hdr='N2QF'.chr(2).chr($profile===N2Q_FAST?0x21:1).random_bytes(16);
            n2q_write_all($f,$hdr);$idx=0;$total=0;
            for(;;) {
                $pt=n2q_read_up_to($input,65536);$kind=$pt===''?1:0;
                $sealed=n2q_seal($profile,$key,pack('P',$idx).str_repeat("\0",8),n2q_file_ad($hdr,$kind,$idx,$total),$pt);
                n2q_write_all($f,chr($kind).pack('V',strlen($sealed)).$sealed);
                if($kind===1) break;
                if($idx===PHP_INT_MAX || $total>PHP_INT_MAX-strlen($pt)) throw new RuntimeException('file too large');
                $idx++;$total+=strlen($pt);
            }
        });
    } finally {fclose($input);}
}
function n2q_decrypt_file(string $key,string $in,string $out): void {
    n2q_validate(N2Q_SECURE,$key);
    $input=fopen($in,'rb');if($input===false) throw new RuntimeException('read open failed');
    try {
        n2q_atomic($out,function($f)use($key,$input) {
            $hdr=n2q_read_exact($input,22);
            if(substr($hdr,0,5)!=="N2QF\2" || !in_array(ord($hdr[5]),[1,0x21],true)) throw new RuntimeException('N2QF v2 required');
            $profile=ord($hdr[5])===0x21?N2Q_FAST:N2Q_SECURE;$idx=0;$total=0;
            for(;;) {
                $rec=n2q_read_exact($input,5);$kind=ord($rec[0]);$len=unpack('V',substr($rec,1,4))[1];
                if(!(($kind===0 && $len>16 && $len<=65552)||($kind===1 && $len===16))) throw new RuntimeException('record length/type');
                $sealed=n2q_read_exact($input,$len);
                $pt=n2q_open($profile,$key,pack('P',$idx).str_repeat("\0",8),n2q_file_ad($hdr,$kind,$idx,$total),$sealed);
                if($pt===null) throw new RuntimeException('authentication failed');
                if($kind===1) {
                    if(n2q_read_up_to($input,1)!=='') throw new RuntimeException('trailing data');
                    break;
                }
                if($idx===PHP_INT_MAX || $total>PHP_INT_MAX-strlen($pt)) throw new RuntimeException('file too large');
                $idx++;$total+=strlen($pt);n2q_write_all($f,$pt);
            }
        });
    } finally {fclose($input);}
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
    echo "N2Q PHP reference — KAT cross-check\n";
    $s = permute([0,0,0,0,0], 12);
    $chk('QP-320 zero p^12', sprintf('%016x %016x', $s[0], $s[1]),
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
