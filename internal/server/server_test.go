package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/oheco/oheco-broker/internal/protocol"
)

func TestHelperProcess(t *testing.T) {
	if os.Getenv("OHECO_TEST_HELPER") != "1" {
		return
	}
	var args []string
	for i, s := range os.Args {
		if s == "--" {
			args = os.Args[i+1:]
			break
		}
	}
	switch args[0] {
	case "echo":
		b, _ := io.ReadAll(os.Stdin)
		os.Stdout.Write(b)
		os.Stderr.Write([]byte("err\x00\xff"))
		os.Exit(7)
	case "large":
		b := bytes.Repeat([]byte("x"), 32768)
		for i := 0; i < 80; i++ {
			os.Stdout.Write(b)
			os.Stderr.Write(b)
		}
	case "metadata":
		cwd, _ := os.Getwd()
		fmt.Printf("%s\n%s\n%s", cwd, os.Getenv("BROKER_VALUE"), strings.Join(args[1:], "|"))
	case "sleep":
		signal.Ignore(syscall.SIGTERM)
		fmt.Fprint(os.Stdout, "ready")
		time.Sleep(time.Minute)
	case "detached":
		b, e := io.ReadAll(os.Stdin)
		if e != nil || len(b) != 0 {
			os.Exit(13)
		}
		fmt.Fprintf(os.Stdout, "ready:%d\n", os.Getpid())
		fmt.Fprintln(os.Stderr, "stderr")
		time.Sleep(time.Minute)
	case "pid":
		signal.Ignore(syscall.SIGTERM)
		fmt.Fprint(os.Stdout, os.Getpid())
		time.Sleep(time.Minute)
	}
	os.Exit(0)
}
func helper(t *testing.T, mode string) protocol.Request {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return protocol.Request{Executable: exe, Args: []string{"-test.run=TestHelperProcess", "--", mode}, Env: []protocol.EnvPair{{Key: "OHECO_TEST_HELPER", Value: "1"}}}
}
func startServer(t *testing.T) (net.Listener, context.CancelFunc, <-chan error) {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, l) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(15 * time.Second):
			t.Error("server failed to stop")
		}
	})
	return l, cancel, done
}
func connect(t *testing.T, l net.Listener) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp4", l.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(20 * time.Second))
	// Fragment every handshake byte deliberately.
	for _, b := range []byte(protocol.Magic) {
		if _, err = c.Write([]byte{b}); err != nil {
			t.Fatal(err)
		}
	}
	b := make([]byte, 8)
	if _, err = io.ReadFull(c, b); err != nil || string(b) != protocol.Magic {
		t.Fatal(string(b), err)
	}
	return c
}
func frame(t *testing.T, c net.Conn) protocol.Frame {
	t.Helper()
	f, err := protocol.Read(c)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func begin(t *testing.T, c net.Conn, r protocol.Request) {
	t.Helper()
	if err := protocol.Write(c, protocol.Start, protocol.EncodeStart(r)); err != nil {
		t.Fatal(err)
	}
	if f := frame(t, c); f.Type != protocol.Started || len(f.Data) != 0 {
		t.Fatalf("not STARTED: %+v", f)
	}
}
func collect(t *testing.T, c net.Conn) ([]byte, []byte, protocol.Frame) {
	t.Helper()
	var out, errout []byte
	for {
		f := frame(t, c)
		switch f.Type {
		case protocol.Stdout:
			out = append(out, f.Data...)
		case protocol.Stderr:
			errout = append(errout, f.Data...)
		default:
			return out, errout, f
		}
	}
}
func TestStdinBinaryAndExit(t *testing.T) {
	l, _, _ := startServer(t)
	c := connect(t, l)
	r := helper(t, "echo")
	r.Stdin = true
	begin(t, c, r)
	want := []byte("input\x00\xff中文")
	protocol.Write(c, protocol.Stdin, want)
	protocol.Write(c, protocol.StdinEOF, nil)
	out, errout, f := collect(t, c)
	if !bytes.Equal(out, want) || !bytes.Equal(errout, []byte("err\x00\xff")) || f.Type != protocol.Exit || len(f.Data) != 12 || binary.BigEndian.Uint32(f.Data[4:]) != 7 {
		t.Fatalf("bad result %q %q %+v", out, errout, f)
	}
}
func TestLargeBothStreams(t *testing.T) {
	l, _, _ := startServer(t)
	c := connect(t, l)
	begin(t, c, helper(t, "large"))
	out, errout, f := collect(t, c)
	if len(out) != 80*32768 || len(errout) != len(out) || f.Type != protocol.Exit {
		t.Fatalf("bad lengths %d %d terminal %d", len(out), len(errout), f.Type)
	}
}
func TestArgumentsCwdEnvironment(t *testing.T) {
	l, _, _ := startServer(t)
	c := connect(t, l)
	r := helper(t, "metadata")
	r.Cwd = t.TempDir()
	r.Args = append(r.Args, "a space", "", "中文\";")
	r.Env = append(r.Env, protocol.EnvPair{Key: "BROKER_VALUE", Value: "v\n中文"})
	begin(t, c, r)
	out, _, f := collect(t, c)
	want := r.Cwd + "\nv\n中文\na space||中文\";"
	if string(out) != want || f.Type != protocol.Exit {
		t.Fatalf("got %q terminal %d", out, f.Type)
	}
}
func TestSpawnFailed(t *testing.T) {
	l, _, _ := startServer(t)
	c := connect(t, l)
	protocol.Write(c, protocol.Start, protocol.EncodeStart(protocol.Request{Executable: "/does/not/exist"}))
	f := frame(t, c)
	if f.Type != protocol.Error || binary.BigEndian.Uint32(f.Data) != protocol.SpawnFailed {
		t.Fatal(f)
	}
}
func TestCancelEscalates(t *testing.T) {
	l, _, _ := startServer(t)
	c := connect(t, l)
	begin(t, c, helper(t, "sleep"))
	if f := frame(t, c); f.Type != protocol.Stdout {
		t.Fatal(f)
	}
	start := time.Now()
	protocol.Write(c, protocol.Cancel, nil)
	_, _, f := collect(t, c)
	if f.Type != protocol.Exit || binary.BigEndian.Uint32(f.Data) != 2 || binary.BigEndian.Uint32(f.Data[8:]) != uint32(syscall.SIGKILL) {
		t.Fatal(f)
	}
	if time.Since(start) < grace || time.Since(start) > 6*time.Second {
		t.Fatal("wrong cancellation grace", time.Since(start))
	}
}
func TestProtocolErrors(t *testing.T) {
	l, _, _ := startServer(t)
	for _, payload := range [][]byte{{}, protocol.EncodeStart(protocol.Request{Executable: "x", Env: []protocol.EnvPair{{Key: "A", Value: "1"}, {Key: "A", Value: "2"}}})} {
		c := connect(t, l)
		protocol.Write(c, protocol.Start, payload)
		f := frame(t, c)
		if f.Type != protocol.Error || binary.BigEndian.Uint32(f.Data) != protocol.Protocol {
			t.Fatal(f)
		}
		c.Close()
	}
	c := connect(t, l)
	begin(t, c, helper(t, "sleep"))
	frame(t, c)
	protocol.Write(c, protocol.StdinEOF, nil) // stdin was disabled
	_, _, f := collect(t, c)
	if f.Type != protocol.Error || binary.BigEndian.Uint32(f.Data) != protocol.Protocol {
		t.Fatal(f)
	}
}
func TestDisconnectAndShutdownReapChild(t *testing.T) {
	for _, shutdown := range []bool{false, true} {
		t.Run(fmt.Sprint(shutdown), func(t *testing.T) {
			l, cancel, _ := startServer(t)
			c := connect(t, l)
			begin(t, c, helper(t, "pid"))
			f := frame(t, c)
			var pid int
			if _, err := fmt.Sscan(string(f.Data), &pid); err != nil {
				t.Fatal(err)
			}
			if shutdown {
				cancel()
			} else {
				c.Close()
			}
			deadline := time.Now().Add(6 * time.Second)
			for time.Now().Before(deadline) {
				if err := syscall.Kill(pid, 0); err == syscall.ESRCH {
					return
				}
				time.Sleep(20 * time.Millisecond)
			}
			t.Fatalf("child %d survived cleanup", pid)
		})
	}
}
func TestPathResolution(t *testing.T) {
	got, err := resolve("sh", "/", []string{"PATH=/system/bin:/usr/bin"})
	if err != nil || !strings.HasSuffix(got, "/sh") {
		t.Fatal(got, err)
	}
	got, err = resolve("./tool", "/a/b", nil)
	if err != nil || got != "/a/b/tool" {
		t.Fatal(got, err)
	}
}
