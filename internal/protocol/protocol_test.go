package protocol

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

func TestStartRoundTrip(t *testing.T) {
	r := Request{Executable: "dotnet", Cwd: "/a space/中文", Args: []string{"build", "", "a\"b"}, Env: []EnvPair{{"K", "line\n值"}}, Stdin: true}
	got, err := DecodeStart(EncodeStart(r))
	if err != nil {
		t.Fatal(err)
	}
	if got.Executable != r.Executable || got.Cwd != r.Cwd || got.Args[1] != "" || got.Env[0] != r.Env[0] || !got.Stdin {
		t.Fatalf("bad roundtrip: %+v", got)
	}
}
func TestRejectStart(t *testing.T) {
	good := EncodeStart(Request{Executable: "x"})
	for n := 0; n < len(good); n++ {
		if _, err := DecodeStart(good[:n]); err == nil {
			t.Fatalf("accepted truncation %d", n)
		}
	}
	for _, r := range []Request{
		{}, {Executable: "a\x00b"}, {Executable: string([]byte{255})},
		{Executable: "x", Env: []EnvPair{{"a=b", "c"}}},
		{Executable: "x", Env: []EnvPair{{"k", "1"}, {"k", "2"}}},
	} {
		if _, err := DecodeStart(EncodeStart(r)); err == nil {
			t.Fatalf("accepted %+v", r)
		}
	}
	if _, err := DecodeStart(append(good, 0)); err == nil {
		t.Fatal("accepted trailing data")
	}
}
func TestFraming(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, Stdout, []byte{0, 255, 1}); err != nil {
		t.Fatal(err)
	}
	f, err := Read(&b)
	if err != nil || f.Type != Stdout || !bytes.Equal(f.Data, []byte{0, 255, 1}) {
		t.Fatal(f, err)
	}
	h := []byte{1, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(h[1:], MaxFrame+1)
	if _, err := Read(bytes.NewReader(h)); err == nil {
		t.Fatal("accepted oversized frame")
	}
	if _, err := Read(bytes.NewReader([]byte{1, 0})); err != io.ErrUnexpectedEOF {
		t.Fatal(err)
	}
}
func TestDetachedCodec(t *testing.T) {
	r := DetachedRequest{Request: Request{Executable: "x", Args: []string{"", "中文"}}, StdoutFile: "a b/输出", StderrFile: ""}
	encoded := EncodeDetached(r)
	got, err := DecodeDetached(encoded)
	if err != nil || got.StdoutFile != r.StdoutFile || got.Args[1] != "中文" {
		t.Fatal(got, err)
	}
	for i := 0; i < len(encoded); i++ {
		if _, err := DecodeDetached(encoded[:i]); err == nil {
			t.Fatalf("accepted truncation %d", i)
		}
	}
	if _, err := DecodeStart(encoded); err == nil {
		t.Fatal("v1 accepted v2 trailing fields")
	}
	if _, err := DecodeDetached(append(encoded, 0)); err == nil {
		t.Fatal("accepted trailing bytes")
	}
	r.Stdin = true
	if _, err := DecodeDetached(EncodeDetached(r)); err == nil {
		t.Fatal("accepted detached stdin")
	}
	r.Stdin = false
	r.StdoutFile = "x\x00y"
	if _, err := DecodeDetached(EncodeDetached(r)); err == nil {
		t.Fatal("accepted NUL path")
	}
}
func FuzzDecodeDetached(f *testing.F) {
	f.Add(EncodeDetached(DetachedRequest{Request: Request{Executable: "x"}}))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) <= MaxFrame {
			_, _ = DecodeDetached(b)
		}
	})
}
func FuzzDecodeStart(f *testing.F) {
	f.Add(EncodeStart(Request{Executable: "dotnet", Args: []string{"--version"}}))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) <= MaxFrame {
			_, _ = DecodeStart(b)
		}
	})
}
