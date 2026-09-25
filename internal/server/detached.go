package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/oheco/oheco-broker/internal/protocol"
)

func detachedOutput(path, cwd string) (*os.File, error) {
	if path == "" {
		return os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(cwd, path)
	}
	// Nonblocking open prevents a FIFO from hanging startup; fstat validates the
	// opened inode instead of relying solely on a race-prone path check.
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_APPEND|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	st, err := f.Stat()
	if err == nil && !st.Mode().IsRegular() {
		err = errors.New("detached output must be a regular file")
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func runDetached(ctx context.Context, cancel context.CancelFunc, s *sender, r protocol.DetachedRequest, slots chan struct{}) {
	select {
	case slots <- struct{}{}:
	default:
		s.fail(protocol.Limit, errors.New("detached direct-child limit reached"))
		return
	}
	handedOff := false
	defer func() {
		if !handedOff {
			<-slots
		}
	}()
	startup := time.AfterFunc(startupTimeout, func() { cancel(); _ = s.c.Close() })
	defer startup.Stop()
	env := environment(r.Env)
	cwd := r.Cwd
	var err error
	if cwd == "" {
		cwd, err = os.Getwd()
	}
	if err == nil {
		cwd, err = filepath.Abs(cwd)
	}
	if err != nil {
		s.fail(protocol.SpawnFailed, err)
		return
	}
	program, err := resolve(r.Executable, cwd, env)
	if err != nil {
		s.fail(protocol.SpawnFailed, err)
		return
	}
	out, err := detachedOutput(r.StdoutFile, cwd)
	if err != nil {
		s.fail(protocol.IO, fmt.Errorf("open detached stdout: %w", err))
		return
	}
	defer out.Close()
	errout := out
	if r.StderrFile != r.StdoutFile {
		errout, err = detachedOutput(r.StderrFile, cwd)
		if err != nil {
			s.fail(protocol.IO, fmt.Errorf("open detached stderr: %w", err))
			return
		}
		defer errout.Close()
	}
	cmd := exec.Command(program, r.Args...)
	cmd.Dir = cwd
	cmd.Env = env
	cmd.Stdout = out
	cmd.Stderr = errout
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if ctx.Err() != nil {
		return
	}
	if err = cmd.Start(); err != nil {
		s.fail(protocol.SpawnFailed, err)
		return
	}
	// Commit point: never roll back a successful detached Start, even if the
	// reply fails, startup deadline expires, or the broker is shutting down.
	handedOff = true
	go func() { _ = cmd.Wait(); <-slots }()
	_ = s.send(protocol.DetachedStarted, protocol.AppendU32(nil, uint32(cmd.Process.Pid)))
}
