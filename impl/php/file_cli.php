<?php
require __DIR__.'/n2qc.php';
if ($argc!==5 || !in_array($argv[1],['encrypt','decrypt'],true)) {
    fwrite(STDERR,"usage: php file_cli.php encrypt|decrypt KEYFILE INPUT OUTPUT\n"); exit(1);
}
try {
    $key=file_get_contents($argv[2]);
    if($key===false || strlen($key)!==16) throw new RuntimeException('key file must contain 16 bytes');
    if($argv[1]==='encrypt') n2q_encrypt_file(N2Q_SECURE,$key,$argv[3],$argv[4]);
    else n2q_decrypt_file($key,$argv[3],$argv[4]);
} catch(Throwable $e) { fwrite(STDERR,$e->getMessage()."\n"); exit(1); }
