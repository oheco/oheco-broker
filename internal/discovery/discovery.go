// Package discovery manages the single-line endpoint and an advisory singleton lock.
package discovery

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

type Discovery struct {
	lock    *os.File
	path    string
	content []byte
}

// Open acquires the private cache lock before publishing an endpoint. Lock files
// are never unlinked: unlinking a flock inode would allow split-brain owners.
func Open() (*Discovery, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	cache := os.Getenv("XDG_CACHE_HOME")
	if cache == "" {
		cache = os.Getenv("TMPDIR")
	}
	if cache == "" {
		return nil, errors.New("XDG_CACHE_HOME or TMPDIR must name a writable private directory")
	}
	lockDir := filepath.Join(cache, "oheco-broker")
	if err = os.MkdirAll(lockDir, 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(lockDir, "service.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("another broker is running (or private filesystem does not support locking): %w", err)
	}
	return &Discovery{lock: f, path: filepath.Join(home, ".oheco", "broker", "endpoint")}, nil
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
		b, err := os.ReadFile(d.path)
		if err == nil && bytes.Equal(b, d.content) {
			_ = os.Remove(d.path)
		}
	}
	if d.lock != nil {
		_ = d.lock.Close()
		d.lock = nil
	}
}
