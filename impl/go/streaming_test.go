package main
import("bytes";"errors";"io";"os";"path/filepath";"testing")
type shortRead struct{input []byte}
func(r *shortRead)Read(out []byte)(int,error){
 if len(r.input)==0{return 0,io.EOF};n:=len(out);if n>7{n=7};if n>len(r.input){n=len(r.input)}
 copy(out,r.input[:n]);r.input=r.input[n:];return n,nil
}
type brokenIO struct{}
func(brokenIO)Read([]byte)(int,error){return 0,errors.New("injected read")}
func(brokenIO)Write([]byte)(int,error){return 0,errors.New("injected write")}
func TestStagingShortReadsAndIO(t *testing.T){
 key:=bytes.Repeat([]byte{4},16);data:=bytes.Repeat([]byte{0x5a},chunkSize+9)
 var sealed,pt bytes.Buffer
 if e:=encryptToStaging(Fast,key,&shortRead{data},&sealed);e!=nil{t.Fatal(e)}
 if e:=decryptToStaging(key,&shortRead{sealed.Bytes()},&pt);e!=nil || !bytes.Equal(pt.Bytes(),data){t.Fatal("stream roundtrip",e)}
 if encryptToStaging(Fast,key,brokenIO{},io.Discard)==nil{t.Fatal("read error ignored")}
 if encryptToStaging(Fast,key,bytes.NewReader(data),brokenIO{})==nil{t.Fatal("write error ignored")}
 if decryptToStaging(key,bytes.NewReader(sealed.Bytes()),brokenIO{})==nil{t.Fatal("output error ignored")}
 if decryptToStaging(key,bytes.NewReader(append(sealed.Bytes(),1)),io.Discard)==nil{t.Fatal("trailer accepted")}
}
func TestStagingFailurePreservesOutput(t *testing.T){
 dir:=t.TempDir();path:=filepath.Join(dir,"out");if e:=os.WriteFile(path,[]byte("keep"),0600);e!=nil{t.Fatal(e)}
 if atomicFile(path,func(w io.Writer)error{_,_=w.Write([]byte("tentative"));return errors.New("injected")})==nil{t.Fatal("ignored error")}
 b,e:=os.ReadFile(path);if e!=nil || string(b)!="keep"{t.Fatal("output replaced",e)}
 entries,e:=os.ReadDir(dir);if e!=nil || len(entries)!=1{t.Fatal("temporary leak",e)}
}
