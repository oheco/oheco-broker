package server

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/oheco/oheco-broker/internal/protocol"
)

func v2connect(t *testing.T, l net.Listener) net.Conn {
	t.Helper()
	c, e := net.DialTimeout("tcp4", l.Addr().String(), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(10 * time.Second))
	io.WriteString(c, protocol.MagicV2)
	b := make([]byte, 8)
	if _, e = io.ReadFull(c, b); e != nil || string(b) != protocol.MagicV2 {
		t.Fatal(string(b), e)
	}
	return c
}
func TestDetachedSurvivesDisconnectAndShutdown(t *testing.T) {
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, l) }()
	dir := t.TempDir()
	log := filepath.Join(dir, "combined.log")
	os.WriteFile(log, []byte("seed\n"), 0600)
	r := protocol.DetachedRequest{Request: helper(t, "detached"), StdoutFile: "combined.log", StderrFile: "combined.log"}
	r.Cwd = dir
	c := v2connect(t, l)
	protocol.Write(c, protocol.StartDetached, protocol.EncodeDetached(r))
	f := frame(t, c)
	if f.Type != protocol.DetachedStarted || len(f.Data) != 4 {
		t.Fatal(f)
	}
	pid := int(binary.BigEndian.Uint32(f.Data))
	if pid < 1 {
		t.Fatal(pid)
	}
	defer func() {
		syscall.Kill(-pid, syscall.SIGKILL)
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if syscall.Kill(pid, 0) == syscall.ESRCH {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Error("detached child not reaped")
	}()
	var b [1]byte
	if n, e := c.Read(b[:]); n != 0 || e != io.EOF {
		t.Fatal("expected terminal ACK and EOF", n, e)
	}
	c.Close()
	deadline := time.Now().Add(3 * time.Second)
	for {
		data, _ := os.ReadFile(log)
		if strings.Contains(string(data), "ready:") && strings.Contains(string(data), "stderr") {
			if !strings.HasPrefix(string(data), "seed\n") {
				t.Fatal("log truncated")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no detached log %q", data)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if pg, e := syscall.Getpgid(pid); e != nil || pg != pid {
		t.Fatal("not independent group", pg, e)
	}
	stop()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("broker waited for detached service")
	}
	if e := syscall.Kill(pid, 0); e != nil {
		t.Fatal("detached killed on broker shutdown", e)
	}
}
func TestDetachedRejectsV1AndInvalidRequest(t *testing.T) {
	l, _, _ := startServer(t)
	r := protocol.DetachedRequest{Request: helper(t, "metadata")}
	c := connect(t, l)
	protocol.Write(c, protocol.StartDetached, protocol.EncodeDetached(r))
	f := frame(t, c)
	if f.Type != protocol.Error || binary.BigEndian.Uint32(f.Data) != protocol.Protocol {
		t.Fatal(f)
	}
	r.Stdin = true
	c = v2connect(t, l)
	protocol.Write(c, protocol.StartDetached, protocol.EncodeDetached(r))
	f = frame(t, c)
	if f.Type != protocol.Error || binary.BigEndian.Uint32(f.Data) != protocol.Protocol {
		t.Fatal(f)
	}
	r.Stdin = false
	r.StdoutFile = t.TempDir()
	c = v2connect(t, l)
	protocol.Write(c, protocol.StartDetached, protocol.EncodeDetached(r))
	f = frame(t, c)
	if f.Type != protocol.Error || binary.BigEndian.Uint32(f.Data) != protocol.IO {
		t.Fatal(f)
	}
}
func TestDetachedCapacity(t *testing.T) {
	// Exercise limit admission without launching 64 persistent processes.
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	slots := make(chan struct{}, 1)
	slots <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runDetached(ctx, cancel, &sender{c: a}, protocol.DetachedRequest{}, slots)
	f, e := protocol.Read(b)
	if e != nil || f.Type != protocol.Error || binary.BigEndian.Uint32(f.Data) != protocol.Limit {
		t.Fatal(f, e)
	}
}
