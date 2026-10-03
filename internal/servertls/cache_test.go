package servertls

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"

	"golang.org/x/crypto/acme/autocert"
)

func TestCachePrivateAtomicPersistence(t *testing.T) {
	path := privateTestDir(t)
	c, err := newPrivateCache(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx := context.Background()
	if _, err := c.Get(ctx, "missing"); err != autocert.ErrCacheMiss {
		t.Fatalf("missing = %v", err)
	}
	if err := c.Delete(ctx, "missing"); err != nil {
		t.Fatal(err)
	}
	if err := c.Put(ctx, "certificate", []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(path, "certificate"), 0400); err != nil {
		t.Fatal(err)
	}
	data, err := c.Get(ctx, "certificate")
	if err != nil || string(data) != "first" {
		t.Fatalf("0400 cache read: %q %v", data, err)
	}
	if err := c.Put(ctx, "certificate", []byte("replacement")); err != nil {
		t.Fatalf("atomic replacement of readonly file: %v", err)
	}
	info, err := os.Lstat(filepath.Join(path, "certificate"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("replacement permissions: %v %v", info, err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := c.Put(canceled, "certificate", []byte("bad")); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Put = %v", err)
	}
	data, err = c.Get(ctx, "certificate")
	if err != nil || string(data) != "replacement" {
		t.Fatalf("canceled Put changed existing file: %q %v", data, err)
	}
	// Independent reads observe only complete values while replacements occur.
	first, second := bytes.Repeat([]byte("a"), 32768), bytes.Repeat([]byte("b"), 65536)
	if err := c.Put(ctx, "certificate", first); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	readerDone := make(chan error, 1)
	go func() {
		for {
			select {
			case <-stop:
				readerDone <- nil
				return
			default:
			}
			data, err := os.ReadFile(filepath.Join(path, "certificate"))
			if err != nil {
				readerDone <- err
				return
			}
			if !bytes.Equal(data, first) && !bytes.Equal(data, second) {
				readerDone <- errors.New("reader observed partial cache data")
				return
			}
		}
	}()
	for range 20 {
		if err := c.Put(ctx, "certificate", second); err != nil {
			t.Fatal(err)
		}
		if err := c.Put(ctx, "certificate", first); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	if err := <-readerDone; err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	c2, err := newPrivateCache(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	data, err = c2.Get(ctx, "certificate")
	if err != nil || !bytes.Equal(data, first) {
		t.Fatalf("cache restart: %v", err)
	}
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v %v", entries, err)
	}
	if err := c2.Delete(ctx, "certificate"); err != nil {
		t.Fatal(err)
	}
	if _, err := c2.Get(ctx, "certificate"); err != autocert.ErrCacheMiss {
		t.Fatalf("Delete failed: %v", err)
	}
}

func TestCacheRejectsUnsafePathsAndFiles(t *testing.T) {
	for _, mode := range []os.FileMode{0755, 0777, 0710, os.ModeSetgid | 0700} {
		t.Run(mode.String(), func(t *testing.T) {
			base := privateTestDir(t)
			path := filepath.Join(base, "unsafe")
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
			if cache, err := newPrivateCache(path, nil); err == nil {
				cache.Close()
				t.Fatal("unsafe directory permissions accepted")
			}
		})
	}
	for _, kind := range []string{"symlink-directory", "symlink-ancestor", "public-file", "writable-file", "symlink-file", "directory-entry", "hardlink-file", "oversized-file"} {
		t.Run(kind, func(t *testing.T) {
			base := privateTestDir(t)
			path := filepath.Join(base, "cache")
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(path, "key")
			switch kind {
			case "symlink-directory":
				link := filepath.Join(base, "link")
				if err := os.Symlink(path, link); err != nil {
					t.Fatal(err)
				}
				path = link
			case "symlink-ancestor":
				link := filepath.Join(base, "link")
				if err := os.Symlink(path, link); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(link, "child")
			case "public-file", "writable-file":
				mode := os.FileMode(0644)
				if kind == "writable-file" {
					mode = 0666
				}
				if err := os.WriteFile(file, []byte("secret"), 0600); err != nil {
					t.Fatal(err)
				}
				// A production umask may mask creation modes to 0600. Set and
				// verify the unsafe fixture explicitly on the private filesystem.
				if err := os.Chmod(file, mode); err != nil {
					t.Fatal(err)
				}
				info, err := os.Stat(file)
				if err != nil || info.Mode().Perm() != mode {
					t.Fatalf("unsafe fixture mode not established: info=%v err=%v", info, err)
				}
			case "symlink-file":
				outside := filepath.Join(base, "outside")
				if err := os.WriteFile(outside, []byte("secret"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, file); err != nil {
					t.Fatal(err)
				}
			case "directory-entry":
				if err := os.Mkdir(file, 0700); err != nil {
					t.Fatal(err)
				}
			case "hardlink-file":
				outside := filepath.Join(base, "outside")
				if err := os.WriteFile(outside, []byte("secret"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(outside, file); err != nil {
					if !errors.Is(err, os.ErrPermission) && !errors.Is(err, syscall.EPERM) {
						t.Fatal(err)
					}
					// HarmonyOS denies creating hard links even on the private
					// filesystem. Exercise the same descriptor metadata check.
					info, statErr := os.Lstat(outside)
					if statErr != nil {
						t.Fatal(statErr)
					}
					stat := *info.Sys().(*syscall.Stat_t)
					stat.Nlink = 2
					if checkFile(ownerInfo{info, stat}) == nil {
						t.Fatal("multiply linked private file accepted")
					}
					t.Log("platform denied hard-link creation; Nlink=2 descriptor check rejected")
					return
				}
			case "oversized-file":
				if err := os.WriteFile(file, bytes.Repeat([]byte("x"), maxCacheFileSize+1), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if cache, err := newPrivateCache(path, nil); err == nil {
				cache.Close()
				t.Fatal("unsafe cache accepted")
			}
		})
	}
}

func TestCacheChecksEveryOperationAndRejectsTraversal(t *testing.T) {
	path := privateTestDir(t)
	c, err := newPrivateCache(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx := context.Background()
	for _, key := range []string{"", ".", "..", "../escape", "/escape", `a\b`, "a\x00b", "a:other"} {
		if err := c.Put(ctx, key, []byte("secret")); err == nil {
			t.Fatalf("invalid Put key %q accepted", key)
		}
		if _, err := c.Get(ctx, key); err == nil {
			t.Fatalf("invalid Get key %q accepted", key)
		}
		if err := c.Delete(ctx, key); err == nil {
			t.Fatalf("invalid Delete key %q accepted", key)
		}
	}
	if err := c.Put(ctx, "key", []byte("secret")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(path, "key"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(ctx, "key"); err == nil {
		t.Fatal("Get ignored changed file permissions")
	}
	if err := c.Put(ctx, "key", []byte("new")); err == nil {
		t.Fatal("Put ignored changed file permissions")
	}
	if err := c.Delete(ctx, "key"); err == nil {
		t.Fatal("Delete ignored changed file permissions")
	}
	if err := os.Chmod(filepath.Join(path, "key"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0777); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(ctx, "key"); err == nil {
		t.Fatal("Get ignored changed directory permissions")
	}
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	moved := path + "-moved"
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(ctx, "key"); err == nil {
		t.Fatal("replaced cache directory accepted")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Put(ctx, "key", nil); err != ErrClosed {
		t.Fatalf("Put after Close = %v", err)
	}
}

type ownerInfo struct {
	os.FileInfo
	stat syscall.Stat_t
}

func (i ownerInfo) Sys() any { return &i.stat }

func TestCacheRejectsOtherOwner(t *testing.T) {
	path := privateTestDir(t)
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat := *info.Sys().(*syscall.Stat_t)
	stat.Uid = uint32(os.Geteuid()) + 1
	if err := checkDirectory(ownerInfo{info, stat}); err == nil {
		t.Fatal("another user's directory accepted")
	}
	file := filepath.Join(path, "key")
	if err := os.WriteFile(file, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	info, err = os.Lstat(file)
	if err != nil {
		t.Fatal(err)
	}
	stat = *info.Sys().(*syscall.Stat_t)
	stat.Uid = uint32(os.Geteuid()) + 1
	if err := checkFile(ownerInfo{info, stat}); err == nil {
		t.Fatal("another user's file accepted")
	}
}

func TestCacheAllowsPrivateUnlinkedDescriptor(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "replaced")
	if err := os.WriteFile(path, []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.Sys().(*syscall.Stat_t).Nlink != 0 {
		t.Fatal("fixture did not reproduce unlinked descriptor")
	}
	if err := checkFile(info); err != nil {
		t.Fatalf("private inode unlinked during atomic replacement rejected: %v", err)
	}
}

func TestCacheConcurrentProviders(t *testing.T) {
	path := privateTestDir(t)
	one, err := newPrivateCache(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer one.Close()
	two, err := newPrivateCache(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer two.Close()
	ctx := context.Background()
	var wg sync.WaitGroup
	for _, cache := range []*privateCache{one, two} {
		wg.Add(1)
		go func(c *privateCache) {
			defer wg.Done()
			for range 10 {
				if err := c.Put(ctx, "key", []byte("private")); err != nil {
					t.Errorf("concurrent Put: %v", err)
					return
				}
			}
		}(cache)
	}
	wg.Wait()
	if data, err := one.Get(ctx, "key"); err != nil || string(data) != "private" {
		t.Fatalf("concurrent cache: %q %v", data, err)
	}
}
