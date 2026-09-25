// Package discovery manages discovery and atomic single-instance startup.
package discovery

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/oheco/oheco-broker/internal/protocol"
)

var ErrAlreadyRunning = errors.New("oheco-broker is already running")

const readyTimeout = 3 * time.Second

type Discovery struct {
	guard   *net.UnixListener
	legacy  *os.File
	path    string
	content []byte
}

// An abstract Unix listener is used ONLY as an atomic lock, never as client IPC.
// Its name depends on shared HOME, not an application's private cache directory.
// The kernel releases it on exit/crash. No permission-sensitive file lives in HOME.
// Scope: the same canonical HOME and network namespace. The private flock remains
// as an interlock with 0.1.0; a responding legacy endpoint is also recognized.
func Open() (*Discovery, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	home, err = filepath.Abs(home)
	if err != nil {
		return nil, err
	}
	if canonical, e := filepath.EvalSymlinks(home); e == nil {
		home = canonical
	}
	d := &Discovery{path: filepath.Join(home, ".oheco", "broker", "endpoint")}
	sum := sha256.Sum256([]byte(d.path))
	name := fmt.Sprintf("@oheco.broker.instance.%x", sum[:20])
	d.guard, err = net.ListenUnix("unix", &net.UnixAddr{Name: name, Net: "unix"})
	if err != nil {
		if errors.Is(err, syscall.EADDRINUSE) {
			return nil, waitExisting(d.path)
		}
		return nil, fmt.Errorf("acquire broker instance guard: %w", err)
	}
	d.guard.SetUnlinkOnClose(false)
	success := false
	defer func() {
		if !success {
			d.Close()
		}
	}()
	if live, e := responding(d.path, 300*time.Millisecond); e != nil {
		return nil, e
	} else if live {
		return nil, ErrAlreadyRunning
	}
	cache := os.Getenv("XDG_CACHE_HOME")
	if cache == "" {
		cache = os.Getenv("TMPDIR")
	}
	if cache != "" {
		dir := filepath.Join(cache, "oheco-broker")
		if err = os.MkdirAll(dir, 0700); err != nil {
			return nil, err
		}
		d.legacy, err = os.OpenFile(filepath.Join(dir, "service.lock"), os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			return nil, err
		}
		if err = syscall.Flock(int(d.legacy.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
				return nil, waitExisting(d.path)
			}
			return nil, fmt.Errorf("acquire legacy broker lock: %w", err)
		}
	}
	if live, e := responding(d.path, 300*time.Millisecond); e != nil {
		return nil, e
	} else if live {
		return nil, ErrAlreadyRunning
	}
	success = true
	return d, nil
}

func waitExisting(path string) error {
	deadline := time.Now().Add(readyTimeout)
	for time.Now().Before(deadline) {
		budget := time.Until(deadline)
		if budget > 300*time.Millisecond {
			budget = 300 * time.Millisecond
		}
		live, err := responding(path, budget)
		if err != nil {
			return err
		}
		if live {
			return ErrAlreadyRunning
		}
		time.Sleep(25 * time.Millisecond)
	}
	return errors.New("broker startup guard is held but no responding endpoint appeared; not starting another instance")
}

// Bound discovery reads during both startup and shutdown. A replaced FIFO or
// oversized file must not hang shutdown or allocate unbounded memory.
func readEndpoint(path string) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("endpoint is not a regular file")
	}
	return io.ReadAll(io.LimitReader(f, 65))
}

// Missing/malformed/refused endpoints are stale. Unreadable/special files are a
// real error, not permission to overwrite possibly live discovery information.
func responding(path string, budget time.Duration) (bool, error) {
	b, err := readEndpoint(path)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return false, nil
		}
		return false, fmt.Errorf("read endpoint: %w", err)
	}
	if len(b) == 0 || len(b) > 64 {
		return false, nil
	}
	addr := string(b)
	if strings.HasSuffix(addr, "\n") {
		addr = strings.TrimSuffix(addr, "\n")
		addr = strings.TrimSuffix(addr, "\r")
	}
	if !strings.HasPrefix(addr, "127.0.0.1:") {
		return false, nil
	}
	port := strings.TrimPrefix(addr, "127.0.0.1:")
	if port == "" {
		return false, nil
	}
	for _, ch := range port {
		if ch < '0' || ch > '9' {
			return false, nil
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return false, nil
	}
	deadline := time.Now().Add(budget)
	c, err := net.DialTimeout("tcp4", addr, budget)
	if err != nil {
		return false, nil
	}
	defer c.Close()
	_ = c.SetDeadline(deadline)
	if _, err = io.WriteString(c, protocol.Magic); err != nil {
		return false, nil
	}
	reply := make([]byte, len(protocol.Magic))
	if _, err = io.ReadFull(c, reply); err != nil {
		return false, nil
	}
	return string(reply) == protocol.Magic, nil
}

func (d *Discovery) Path() string { return d.path }
func (d *Discovery) Publish(address string) error {
	dir := filepath.Dir(d.path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".endpoint-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	content := []byte(address + "\n")
	if _, err = f.Write(content); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), d.path); err != nil {
		return err
	}
	d.content = content
	return nil
}
func (d *Discovery) Close() {
	if len(d.content) > 0 {
		b, err := readEndpoint(d.path)
		if err == nil && bytes.Equal(b, d.content) {
			_ = os.Remove(d.path)
		}
		d.content = nil
	}
	if d.legacy != nil {
		_ = d.legacy.Close()
		d.legacy = nil
	}
	if d.guard != nil {
		_ = d.guard.Close()
		d.guard = nil
	}
}
