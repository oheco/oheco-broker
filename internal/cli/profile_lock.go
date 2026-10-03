package cli

import (
	"errors"
	"os"
	"strings"
	"syscall"
)

func (o *rootOptions) lockProfile() (func(), error) {
	path, err := o.path()
	if err != nil {
		return nil, err
	}
	return acquireProfile(path)
}

// Kernel-owned advisory locks serialize profile mutations and release on crash.
// Keep the empty lock file: unlinking it could let another process lock a new
// inode while an older command still holds the previous inode's lock.
func acquireProfile(path string) (func(), error) {
	key := strings.TrimSuffix(path, ".pending")
	if err := privateDirectory(key); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(key+".lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		file.Close()
		return nil, errors.New("profile lock must be a private regular file")
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Uid != uint32(os.Getuid()) {
		file.Close()
		return nil, errors.New("profile lock belongs to another user")
	}
	if err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, errors.New("account profile is being modified by another command; retry when it finishes")
		}
		return nil, err
	}
	return func() { _ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN); _ = file.Close() }, nil
}
