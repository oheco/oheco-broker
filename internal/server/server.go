// Package server implements connection-bound command execution on Unix/ohos.
package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/oheco/oheco-broker/internal/protocol"
)

const startupTimeout = 3 * time.Second
const writeTimeout = 10 * time.Second
const grace = 2 * time.Second
const maxConnections = 32

// Serve owns l; cancellation closes the listener and cancels managed commands.
func Serve(ctx context.Context, l net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { <-ctx.Done(); _ = l.Close() }()
	var wg sync.WaitGroup
	defer wg.Wait()
	slots := make(chan struct{}, maxConnections)
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			cancel()
			return err
		}
		select {
		case slots <- struct{}{}:
			wg.Add(1)
			go func() { defer wg.Done(); defer func() { <-slots }(); handle(ctx, c) }()
		default:
			_ = c.Close()
		}
	}
}

type sender struct {
	c  net.Conn
	mu sync.Mutex
}

func (s *sender) send(t byte, b []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.c.SetWriteDeadline(time.Now().Add(writeTimeout))
	return protocol.Write(s.c, t, b)
}
func (s *sender) fail(code uint32, err error) {
	_ = s.send(protocol.Error, protocol.EncodeError(code, err))
}

func handle(parent context.Context, c net.Conn) {
	defer c.Close()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	// Also interrupt an idle or partial handshake during service shutdown.
	guardDone := make(chan struct{})
	defer close(guardDone)
	go func() {
		select {
		case <-parent.Done():
			_ = c.Close()
		case <-guardDone:
		}
	}()
	s := &sender{c: c}
	_ = c.SetDeadline(time.Now().Add(startupTimeout))
	magic := make([]byte, len(protocol.Magic))
	if _, err := io.ReadFull(c, magic); err != nil || string(magic) != protocol.Magic {
		return
	}
	if _, err := io.WriteString(c, protocol.Magic); err != nil {
		return
	}
	_ = c.SetDeadline(time.Now().Add(startupTimeout))
	f, err := protocol.Read(c)
	if err != nil {
		return
	}
	if f.Type != protocol.Start {
		s.fail(protocol.Protocol, errors.New("expected START"))
		return
	}
	req, err := protocol.DecodeStart(f.Data)
	if err != nil {
		s.fail(protocol.Protocol, err)
		return
	}
	_ = c.SetDeadline(time.Time{})
	run(ctx, cancel, s, req)
}

func environment(overrides []protocol.EnvPair) []string {
	env := os.Environ()
	for _, pair := range overrides {
		prefix := pair.Key + "="
		found := false
		for i, v := range env {
			if strings.HasPrefix(v, prefix) {
				env[i] = prefix + pair.Value
				found = true
				break
			}
		}
		if !found {
			env = append(env, prefix+pair.Value)
		}
	}
	return env
}
func envValue(env []string, key string) string {
	for _, s := range env {
		if v, ok := strings.CutPrefix(s, key+"="); ok {
			return v
		}
	}
	return ""
}

// Resolve with the request's cwd and effective PATH, not the broker's unmodified PATH.
func resolve(name, cwd string, env []string) (string, error) {
	if strings.ContainsRune(name, '/') {
		if !filepath.IsAbs(name) {
			name = filepath.Join(cwd, name)
		}
		return name, nil
	}
	for _, dir := range strings.Split(envValue(env, "PATH"), string(os.PathListSeparator)) {
		if !filepath.IsAbs(dir) {
			dir = filepath.Join(cwd, dir)
		}
		p := filepath.Join(dir, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Mode()&0111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("executable %q not found in effective PATH", name)
}

type controlFailure struct {
	code uint32
	err  error
}

func run(ctx context.Context, cancel context.CancelFunc, s *sender, r protocol.Request) {
	// Bound the wire startup exchange even if resolution or exec is slow. OS
	// filesystem/exec syscalls themselves are not interruptible by Go context;
	// if Start returns late, reap the child without acknowledging it.
	startup := time.AfterFunc(startupTimeout, func() { cancel(); _ = s.c.Close() })
	defer startup.Stop()
	env := environment(r.Env)
	cwd := r.Cwd
	if cwd == "" {
		var err error
		cwd, err = os.Getwd()
		if err != nil {
			s.fail(protocol.SpawnFailed, err)
			return
		}
	}
	cwd, err := filepath.Abs(cwd)
	if err != nil {
		s.fail(protocol.SpawnFailed, err)
		return
	}
	program, err := resolve(r.Executable, cwd, env)
	if err != nil {
		s.fail(protocol.SpawnFailed, err)
		return
	}
	cmd := exec.Command(program, r.Args...)
	cmd.Dir = cwd
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	outR, outW, err := os.Pipe()
	if err != nil {
		s.fail(protocol.IO, err)
		return
	}
	defer outR.Close()
	defer outW.Close()
	errR, errW, err := os.Pipe()
	if err != nil {
		s.fail(protocol.IO, err)
		return
	}
	defer errR.Close()
	defer errW.Close()
	cmd.Stdout = outW
	cmd.Stderr = errW
	var inR, inW *os.File
	if r.Stdin {
		inR, inW, err = os.Pipe()
		if err != nil {
			s.fail(protocol.IO, err)
			return
		}
		defer inR.Close()
		defer inW.Close()
		cmd.Stdin = inR
	}
	if err = ctx.Err(); err != nil {
		return
	}
	if err = cmd.Start(); err != nil {
		s.fail(protocol.SpawnFailed, err)
		return
	}
	pid := cmd.Process.Pid
	if ctx.Err() != nil {
		_ = syscall.Kill(-pid, syscall.SIGKILL)
		_ = cmd.Wait()
		return
	}
	_ = outW.Close()
	_ = errW.Close()
	if inR != nil {
		_ = inR.Close()
	}
	// Never send output until STARTED has been acknowledged on the wire.
	if err = s.send(protocol.Started, nil); err != nil {
		cancel()
	}
	startup.Stop()
	outputDone := make(chan error, 2)
	pump := func(file *os.File, kind byte) {
		buf := make([]byte, 32768)
		for {
			n, e := file.Read(buf)
			if n > 0 {
				if werr := s.send(kind, buf[:n]); werr != nil {
					cancel()
					_ = s.c.Close()
					outputDone <- werr
					return
				}
			}
			if e != nil {
				if errors.Is(e, io.EOF) {
					e = nil
				}
				outputDone <- e
				return
			}
		}
	}
	go pump(outR, protocol.Stdout)
	go pump(errR, protocol.Stderr)
	controls := make(chan controlFailure, 1)
	input := make(chan []byte, 16) // bounded at 1 MiB; nil element denotes EOF
	if inW != nil {
		go func() {
			defer inW.Close()
			discard := false
			for {
				select {
				case <-ctx.Done():
					return
				case b := <-input:
					if b == nil {
						return
					}
					if !discard {
						if _, e := inW.Write(b); e != nil {
							discard = true
						}
					}
				}
			}
		}()
	}
	go readControls(ctx, cancel, s.c, r.Stdin, input, controls)
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	var waitErr error
	cancelled := false
	select {
	case waitErr = <-waited:
	case <-ctx.Done():
		cancelled = true
		_ = syscall.Kill(-pid, syscall.SIGTERM)
		timer := time.NewTimer(grace)
		select {
		case waitErr = <-waited:
			if !timer.Stop() {
				<-timer.C
			}
		case <-timer.C:
			_ = syscall.Kill(-pid, syscall.SIGKILL)
			waitErr = <-waited
		}
	}
	// This is a managed command, not a route to detached build servers.
	_ = syscall.Kill(-pid, syscall.SIGKILL)
	if inW != nil {
		_ = inW.Close()
	}
	// Give pipe readers time to forward buffered data; escaped descendants must
	// not hold a request forever. A forced drain is reported as IO, not success.
	drainTimer := time.NewTimer(grace)
	var outputErr error
	for i := 0; i < 2; i++ {
		select {
		case e := <-outputDone:
			if e != nil {
				outputErr = e
			}
		case <-drainTimer.C:
			outputErr = errors.New("output drain timed out (a descendant may still hold a pipe)")
			_ = outR.Close()
			_ = errR.Close()
			// Interrupt a blocked network sender too; the client sees CONNECTION_LOST.
			_ = s.c.SetWriteDeadline(time.Now())
			for ; i < 2; i++ {
				<-outputDone
			}
		}
	}
	drainTimer.Stop()
	select {
	case failure := <-controls:
		s.fail(failure.code, failure.err)
		return
	default:
	}
	if outputErr != nil {
		s.fail(protocol.IO, outputErr)
		return
	}
	var exitErr *exec.ExitError
	if waitErr != nil && !errors.As(waitErr, &exitErr) {
		s.fail(protocol.IO, waitErr)
		return
	}
	reason := uint32(0)
	code := cmd.ProcessState.ExitCode()
	sig := uint32(0)
	if status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		reason = 1
		sig = uint32(status.Signal())
	}
	if cancelled {
		reason = 2
	}
	if err := s.send(protocol.Exit, protocol.EncodeExit(reason, code, sig)); err != nil && ctx.Err() == nil {
		log.Printf("result delivery failed: %v", err)
	}
}

func readControls(ctx context.Context, cancel context.CancelFunc, c net.Conn, enabled bool, input chan<- []byte, failures chan<- controlFailure) {
	defer cancel()
	fail := func(code uint32, e error) {
		select {
		case failures <- controlFailure{code, e}:
		default:
		}
	}
	closed := !enabled
	for {
		f, err := protocol.Read(c)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				var ne net.Error
				if !errors.As(err, &ne) {
					fail(protocol.Protocol, err)
				}
			}
			return
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
		switch f.Type {
		case protocol.Cancel:
			if len(f.Data) != 0 {
				fail(protocol.Protocol, errors.New("CANCEL must be empty"))
			}
			return
		case protocol.Stdin:
			if closed || len(f.Data) == 0 || len(f.Data) > protocol.MaxChunk {
				fail(protocol.Protocol, errors.New("invalid STDIN or stdin already closed"))
				return
			}
			select {
			case input <- f.Data:
			case <-ctx.Done():
				return
			default:
				fail(protocol.Limit, errors.New("stdin queue limit exceeded"))
				return
			}
		case protocol.StdinEOF:
			if closed || len(f.Data) != 0 {
				fail(protocol.Protocol, errors.New("invalid or repeated STDIN_EOF"))
				return
			}
			closed = true
			select {
			case input <- nil:
			case <-ctx.Done():
				return
			default:
				fail(protocol.Limit, errors.New("stdin queue limit exceeded"))
				return
			}
		default:
			fail(protocol.Protocol, errors.New("unexpected client frame"))
			return
		}
	}
}
