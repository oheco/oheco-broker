package discovery

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPublishLockAndCleanup(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", filepath.Join(root, "home"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(root, "cache"))
	d, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if other, err := Open(); err == nil {
		other.Close()
		t.Fatal("second lock succeeded")
	}
	if err = d.Publish("127.0.0.1:12345"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(d.Path())
	if err != nil || string(b) != "127.0.0.1:12345\n" {
		t.Fatal(string(b), err)
	}
	d.Close()
	if _, err = os.Stat(d.Path()); !os.IsNotExist(err) {
		t.Fatal("endpoint not cleaned", err)
	}
	next, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if err = next.Publish("127.0.0.1:12346"); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(next.Path(), []byte("127.0.0.1:12347\n"), 0600); err != nil {
		t.Fatal(err)
	}
	next.Close()
	if b, err = os.ReadFile(next.Path()); err != nil || string(b) != "127.0.0.1:12347\n" {
		t.Fatal("removed another endpoint", err)
	}
}
