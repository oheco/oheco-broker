package discovery

import (
	"os"
	"syscall"
	"testing"
	"time"
)

func TestReplacedEndpointCleanupIsBounded(t *testing.T) {
	path := setup(t)
	d, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	if err = d.Publish("127.0.0.1:12345"); err != nil {
		d.Close()
		t.Fatal(err)
	}
	if err = os.Remove(path); err != nil {
		d.Close()
		t.Fatal(err)
	}
	if err = syscall.Mkfifo(path, 0600); err != nil {
		d.Close()
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { d.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cleanup blocked on replaced FIFO")
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode()&os.ModeNamedPipe == 0 {
		t.Fatal("removed replacement", st, err)
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	next, err := Open()
	if err != nil {
		t.Fatal("guard was not released", err)
	}
	next.Close()
}
