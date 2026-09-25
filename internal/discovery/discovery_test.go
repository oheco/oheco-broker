package discovery

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/oheco/oheco-broker/internal/protocol"
)

func setup(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	t.Setenv("HOME", filepath.Join(root, "home"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(root, "cache"))
	return filepath.Join(root, "home", ".oheco", "broker", "endpoint")
}
func greeting(t *testing.T, reply string) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(time.Second))
				b := make([]byte, 8)
				if _, e := io.ReadFull(c, b); e == nil {
					_, _ = io.WriteString(c, reply)
				}
			}()
		}
	}()
	return l
}
func TestPublishCrossCacheAndCleanup(t *testing.T) {
	path := setup(t)
	l := greeting(t, protocol.Magic)
	d, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err = d.Publish(l.Addr().String()); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CACHE_HOME", filepath.Join(t.TempDir(), "other-cache"))
	other, err := Open()
	if other != nil || !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("duplicate: %v %v", other, err)
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != l.Addr().String()+"\n" {
		t.Fatal(string(b), err)
	}
	d.Close()
	if _, err = os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("endpoint not cleaned", err)
	}
	next, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if err = next.Publish(l.Addr().String()); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, []byte("127.0.0.1:12347\n"), 0600); err != nil {
		t.Fatal(err)
	}
	next.Close()
	b, err = os.ReadFile(path)
	if err != nil || string(b) != "127.0.0.1:12347\n" {
		t.Fatal("removed another endpoint", err)
	}
}
func TestRespondingLegacyEndpoint(t *testing.T) {
	path := setup(t)
	l := greeting(t, protocol.Magic)
	os.MkdirAll(filepath.Dir(path), 0700)
	os.WriteFile(path, []byte(l.Addr().String()+"\n"), 0600)
	d, err := Open()
	if d != nil || !errors.Is(err, ErrAlreadyRunning) {
		t.Fatal(d, err)
	}
	if _, err = os.Stat(path); err != nil {
		t.Fatal("duplicate deleted live endpoint", err)
	}
}
func TestStaleOrNonBrokerEndpoint(t *testing.T) {
	path := setup(t)
	l := greeting(t, "NOTBROK\n")
	os.MkdirAll(filepath.Dir(path), 0700)
	for _, value := range []string{"", "invalid", "127.0.0.2:123", l.Addr().String() + "\n"} {
		os.WriteFile(path, []byte(value), 0600)
		d, err := Open()
		if err != nil {
			t.Fatal(value, err)
		}
		d.Close()
	}
}
func TestConcurrentStartup(t *testing.T) {
	setup(t)
	l := greeting(t, protocol.Magic)
	var wg sync.WaitGroup
	var mu sync.Mutex
	winners := []*Discovery{}
	failures := []error{}
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d, err := Open()
			if err == nil {
				err = d.Publish(l.Addr().String())
				mu.Lock()
				winners = append(winners, d)
				mu.Unlock()
			}
			if err != nil && !errors.Is(err, ErrAlreadyRunning) {
				mu.Lock()
				failures = append(failures, err)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	defer func() {
		for _, d := range winners {
			d.Close()
		}
	}()
	if len(winners) != 1 || len(failures) > 0 {
		t.Fatalf("winners=%d failures=%v", len(winners), failures)
	}
}
func TestBusyWithoutReadyIsRealError(t *testing.T) {
	setup(t)
	d, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	other, err := Open()
	if other != nil || err == nil || errors.Is(err, ErrAlreadyRunning) {
		t.Fatal(other, err)
	}
}
func TestUnreadableOrSpecialEndpoint(t *testing.T) {
	path := setup(t)
	os.MkdirAll(path, 0700)
	d, err := Open()
	if d != nil || err == nil || errors.Is(err, ErrAlreadyRunning) {
		t.Fatal(d, err)
	}
}
