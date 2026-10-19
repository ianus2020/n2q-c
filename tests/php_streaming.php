<?php
require_once __DIR__.'/../impl/php/n2qc.php';
function check_stream($ok) {if(!$ok) throw new RuntimeException('streaming regression');}
$input=fopen('php://memory','w+b');fwrite($input,'abcdef');rewind($input);
check_stream(n2q_read_exact($input,3)==='abc');
check_stream(n2q_read_up_to($input,7)==='def');
try {n2q_read_exact($input,1);throw new LogicException('truncation accepted');}
catch(RuntimeException $e) {} finally {fclose($input);}
class N2QBrokenWriter {
    public $context;
    function stream_open($path,$mode,$options,&$opened_path) {return true;}
    function stream_write($data) {return 0;}
}
stream_wrapper_register('n2qbroken',N2QBrokenWriter::class);
$broken=fopen('n2qbroken://out','wb');
try {n2q_write_all($broken,'data');throw new LogicException('write failure accepted');}
catch(RuntimeException $e) {} finally {fclose($broken);stream_wrapper_unregister('n2qbroken');}
$dir=sys_get_temp_dir().'/n2q-php-'.bin2hex(random_bytes(8));
check_stream(mkdir($dir,0700));$out=$dir.'/out';file_put_contents($out,'keep');
try {
    try {
        n2q_atomic($out,function($f){n2q_write_all($f,'tentative');throw new RuntimeException('injected');});
        throw new LogicException('staging failure accepted');
    } catch(RuntimeException $e) {}
    check_stream(file_get_contents($out)==='keep');
    check_stream(count(scandir($dir))===3);
} finally {unlink($out);rmdir($dir);}
echo "PHP short-read, truncation, write-error and staging cleanup PASS\n";
