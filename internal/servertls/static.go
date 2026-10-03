package servertls

import (
	"errors"
	"io"
	"os"
	"syscall"
)

// readStaticFile validates the descriptor actually read, rather than trusting
// only the path checked before opening. A public certificate may have public
// permissions; a private key must satisfy the cache's strict file rules.
func readStaticFile(path string, private bool) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, errors.New("certificate and key paths must be regular files, without symbolic links")
	}
	if private {
		if err := checkFile(before); err != nil {
			return nil, err
		}
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || !sameStaticFileVersion(before, opened) {
		return nil, errors.New("certificate or key file changed while opening")
	}
	if private {
		if err := checkFile(opened); err != nil {
			return nil, err
		}
	}
	if opened.Size() > maxCacheFileSize {
		return nil, errors.New("certificate or key file exceeds size limit")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxCacheFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxCacheFileSize {
		return nil, errors.New("certificate or key file exceeds size limit")
	}
	after, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !sameStaticFileVersion(opened, after) || !after.Mode().IsRegular() {
		return nil, errors.New("certificate or key file changed while reading")
	}
	if private {
		if err := checkFile(after); err != nil {
			return nil, err
		}
	}
	return data, nil
}

// Inode identity alone does not detect a renewal writer truncating or replacing
// bytes in place. ctime also catches writes that restore the original mtime.
// Atime is deliberately ignored because our own read may update it.
func sameStaticFileVersion(a, b os.FileInfo) bool {
	if !os.SameFile(a, b) || a.Mode() != b.Mode() || a.Size() != b.Size() || !a.ModTime().Equal(b.ModTime()) {
		return false
	}
	left, leftOK := a.Sys().(*syscall.Stat_t)
	right, rightOK := b.Sys().(*syscall.Stat_t)
	return leftOK && rightOK && left.Ctim == right.Ctim
}
