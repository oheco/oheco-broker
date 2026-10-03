package servertls

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/crypto/acme/autocert"
)

const maxCacheFileSize = 1 << 20

// privateCache anchors operations to an open directory. We never repair unsafe
// permissions with chmod: on filesystems ignoring modes this would give a false
// guarantee. O_NOFOLLOW and descriptor checks also cover symlink replacement
// between Lstat and OpenFile. The directory and its contents must be user-owned.
type privateCache struct {
	mu     sync.Mutex
	root   *os.Root
	path   string
	closed bool
	emit   func(Event)
}

func newPrivateCache(path string, emit func(Event)) (*privateCache, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, errors.New("servertls: invalid cache directory")
	}
	if err := rejectSymlinkComponents(absolute); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(absolute, 0700); err != nil {
		return nil, fmt.Errorf("servertls: create private cache: %w", err)
	}
	// Inspect again because creation may have traversed an existing component.
	if err := rejectSymlinkComponents(absolute); err != nil {
		return nil, err
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return nil, err
	}
	if err := checkDirectory(info); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(absolute)
	if err != nil {
		return nil, err
	}
	cache := &privateCache{root: root, path: absolute, emit: emit}
	if err := cache.checkRoot(); err != nil {
		root.Close()
		return nil, err
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		root.Close()
		return nil, errors.New("servertls: cache directory changed while opening")
	}
	dir, err := root.Open(".")
	if err != nil {
		root.Close()
		return nil, err
	}
	entries, readErr := dir.ReadDir(-1)
	closeErr := dir.Close()
	if readErr != nil || closeErr != nil {
		root.Close()
		return nil, errors.Join(readErr, closeErr)
	}
	for _, entry := range entries {
		if err := cache.checkEntry(entry.Name(), false); err != nil {
			root.Close()
			return nil, err
		}
	}
	return cache, nil
}

func rejectSymlinkComponents(path string) error {
	for current := filepath.Clean(path); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("servertls: inspect cache path: %w", err)
		}
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return errors.New("servertls: cache path must not contain symbolic links")
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
	}
}

func currentOwner(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}

func checkDirectory(info os.FileInfo) error {
	if !info.IsDir() || info.Mode() != os.ModeDir|0700 || !currentOwner(info) {
		return errors.New("servertls: cache directory must be owned by the current user with mode 0700; use a filesystem that enforces permissions")
	}
	return nil
}

func checkFile(info os.FileInfo) error {
	mode := info.Mode()
	stat, ok := info.Sys().(*syscall.Stat_t)
	// Atomic replacement by another provider can unlink an inode after Root's
	// lookup opens it but before fstat, yielding Nlink=0. Such a descriptor is
	// still private; only multiple links can expose the data under another name.
	if !mode.IsRegular() || (mode != 0600 && mode != 0400) || !currentOwner(info) || !ok || stat.Nlink > 1 {
		return errors.New("servertls: cache files must be regular, without hard links, owned by the current user with mode 0600 or 0400")
	}
	if info.Size() > maxCacheFileSize {
		return errors.New("servertls: cache file exceeds size limit")
	}
	return nil
}

func cacheKey(key string) error {
	if key == "" || key == "." || key == ".." || strings.ContainsAny(key, `/\:*?"<>|`) {
		return errors.New("servertls: invalid cache key")
	}
	for _, ch := range key {
		if ch < 0x20 || ch > 0x7e {
			return errors.New("servertls: invalid cache key")
		}
	}
	return nil
}

func (c *privateCache) checkRoot() error {
	if c.closed {
		return ErrClosed
	}
	if err := rejectSymlinkComponents(c.path); err != nil {
		return err
	}
	actual, err := os.Lstat(c.path)
	if err != nil {
		return err
	}
	anchored, err := c.root.Stat(".")
	if err != nil {
		return err
	}
	if !os.SameFile(actual, anchored) {
		return errors.New("servertls: cache directory was replaced")
	}
	return checkDirectory(anchored)
}

func (c *privateCache) checkEntry(key string, missingOK bool) error {
	info, err := c.root.Lstat(key)
	if os.IsNotExist(err) && missingOK {
		return nil
	}
	if err != nil {
		return err
	}
	return checkFile(info)
}

func (c *privateCache) Get(ctx context.Context, key string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := cacheKey(key); err != nil {
		return nil, err
	}
	if err := c.checkRoot(); err != nil {
		return nil, err
	}
	if err := c.checkEntry(key, false); err != nil {
		if os.IsNotExist(err) {
			return nil, autocert.ErrCacheMiss
		}
		return nil, err
	}
	file, err := c.root.OpenFile(key, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if err := checkFile(info); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(file, maxCacheFileSize+1))
	if err == nil && len(data) > maxCacheFileSize {
		err = errors.New("servertls: cache file exceeds size limit")
	}
	if err == nil {
		err = ctx.Err()
	}
	return data, err
}

func (c *privateCache) Put(ctx context.Context, key string, data []byte) (result error) {
	// Emit after releasing the lock, allowing a logger to inspect provider state.
	defer func() {
		if c.emit != nil {
			if result != nil {
				c.emit(Event{Kind: "cache_error"})
			} else if expiry, ok := cachedCertificate(data); ok && !strings.HasSuffix(key, "+token") {
				c.emit(Event{Kind: "certificate_stored", NotAfter: expiry.NotAfter})
			}
		}
	}()
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := cacheKey(key); err != nil {
		return err
	}
	if len(data) > maxCacheFileSize {
		return errors.New("servertls: cache data exceeds size limit")
	}
	if err := c.checkRoot(); err != nil {
		return err
	}
	if err := c.checkEntry(key, true); err != nil {
		return err
	}
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return err
	}
	temporary := ".autocert-" + hex.EncodeToString(token[:])
	file, err := c.root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer c.root.Remove(temporary)
	info, err := file.Stat()
	if err == nil {
		err = checkFile(info)
	}
	if err == nil {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	err = errors.Join(err, file.Close())
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := c.checkRoot(); err != nil {
		return err
	}
	if err := c.checkEntry(key, true); err != nil {
		return err
	}
	if err := c.root.Rename(temporary, key); err != nil {
		return err
	}
	// Persist the rename as well as the file contents before reporting success.
	directory, err := c.root.Open(".")
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}

func cachedCertificate(data []byte) (*x509.Certificate, bool) {
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		data = rest
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			return cert, err == nil
		}
	}
	return nil, false
}

func (c *privateCache) Delete(ctx context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := cacheKey(key); err != nil {
		return err
	}
	if err := c.checkRoot(); err != nil {
		return err
	}
	if err := c.checkEntry(key, true); err != nil {
		return err
	}
	err := c.root.Remove(key)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func (c *privateCache) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	return c.root.Close()
}
