// Package protocol implements the small, dependency-free broker wire format.
package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

const Magic = "OHECOB1\n"
const MagicV2 = "OHECOB2\n"
const MaxFrame = 1 << 20
const MaxChunk = 65536
const MaxItems = 4096

const (
	Start byte = iota + 1
	Started
	Stdin
	StdinEOF
	Stdout
	Stderr
	Cancel
	Exit
	Error
	StartDetached
	DetachedStarted
)
const (
	OK uint32 = iota
	Unavailable
	Protocol
	SpawnFailed
	ConnectionLost
	InvalidArgument
	Timeout
	IO
	Limit
)

type Request struct {
	Executable string
	Cwd        string
	Args       []string
	Env        []EnvPair
	Stdin      bool
}
type EnvPair struct{ Key, Value string }

type Frame struct {
	Type byte
	Data []byte
}

func Read(r io.Reader) (Frame, error) {
	var h [5]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return Frame{}, err
	}
	n := binary.BigEndian.Uint32(h[1:])
	if n > MaxFrame {
		return Frame{}, fmt.Errorf("frame exceeds %d bytes", MaxFrame)
	}
	f := Frame{Type: h[0], Data: make([]byte, int(n))}
	_, err := io.ReadFull(r, f.Data)
	return f, err
}

func Write(w io.Writer, kind byte, data []byte) error {
	if len(data) > MaxFrame {
		return errors.New("frame too large")
	}
	var h [5]byte
	h[0] = kind
	binary.BigEndian.PutUint32(h[1:], uint32(len(data)))
	if err := writeAll(w, h[:]); err != nil {
		return err
	}
	return writeAll(w, data)
}
func writeAll(w io.Writer, p []byte) error {
	for len(p) != 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

type decoder struct {
	b   []byte
	err error
}

func (d *decoder) u32() uint32 {
	if d.err != nil {
		return 0
	}
	if len(d.b) < 4 {
		d.err = io.ErrUnexpectedEOF
		return 0
	}
	n := binary.BigEndian.Uint32(d.b)
	d.b = d.b[4:]
	return n
}
func (d *decoder) str() string {
	n := d.u32()
	if d.err != nil {
		return ""
	}
	if uint64(n) > uint64(len(d.b)) {
		d.err = io.ErrUnexpectedEOF
		return ""
	}
	p := d.b[:int(n)]
	d.b = d.b[int(n):]
	if !utf8.Valid(p) || strings.IndexByte(string(p), 0) >= 0 {
		d.err = errors.New("invalid UTF-8 string or embedded NUL")
		return ""
	}
	return string(p)
}
func (d *decoder) count() int {
	n := d.u32()
	if n > MaxItems {
		d.err = errors.New("too many items")
		return 0
	}
	return int(n)
}

func decodeStart(d *decoder) (Request, error) {
	r := Request{Executable: d.str(), Cwd: d.str()}
	argc := d.count()
	for i := 0; i < argc && d.err == nil; i++ {
		r.Args = append(r.Args, d.str())
	}
	envc := d.count()
	seen := make(map[string]bool)
	for i := 0; i < envc && d.err == nil; i++ {
		k, v := d.str(), d.str()
		if k == "" || strings.Contains(k, "=") || seen[k] {
			d.err = errors.New("invalid or duplicate environment key")
		}
		seen[k] = true
		r.Env = append(r.Env, EnvPair{k, v})
	}
	if d.err != nil {
		return Request{}, d.err
	}
	if r.Executable == "" {
		return Request{}, errors.New("executable is empty")
	}
	if len(d.b) < 1 || d.b[0] > 1 {
		return Request{}, errors.New("invalid stdin flag")
	}
	r.Stdin = d.b[0] == 1
	d.b = d.b[1:]
	return r, nil
}

func DecodeStart(p []byte) (Request, error) {
	d := decoder{b: p}
	r, err := decodeStart(&d)
	if err == nil && len(d.b) != 0 {
		err = errors.New("trailing START bytes")
	}
	return r, err
}

type DetachedRequest struct {
	Request
	StdoutFile, StderrFile string
}

func DecodeDetached(p []byte) (DetachedRequest, error) {
	d := decoder{b: p}
	r, err := decodeStart(&d)
	if err != nil {
		return DetachedRequest{}, err
	}
	if r.Stdin {
		return DetachedRequest{}, errors.New("detached stdin must be disabled")
	}
	out, errout := d.str(), d.str()
	if d.err != nil {
		return DetachedRequest{}, d.err
	}
	if len(d.b) != 0 {
		return DetachedRequest{}, errors.New("trailing detached START bytes")
	}
	return DetachedRequest{r, out, errout}, nil
}
func EncodeDetached(r DetachedRequest) []byte {
	b := EncodeStart(r.Request)
	b = AppendString(b, r.StdoutFile)
	return AppendString(b, r.StderrFile)
}
func AppendU32(b []byte, n uint32) []byte { return binary.BigEndian.AppendUint32(b, n) }
func AppendString(b []byte, s string) []byte {
	b = AppendU32(b, uint32(len(s)))
	return append(b, s...)
}
func EncodeStart(r Request) []byte {
	b := AppendString(nil, r.Executable)
	b = AppendString(b, r.Cwd)
	b = AppendU32(b, uint32(len(r.Args)))
	for _, a := range r.Args {
		b = AppendString(b, a)
	}
	b = AppendU32(b, uint32(len(r.Env)))
	for _, e := range r.Env {
		b = AppendString(b, e.Key)
		b = AppendString(b, e.Value)
	}
	if r.Stdin {
		return append(b, 1)
	}
	return append(b, 0)
}
func EncodeError(code uint32, err error) []byte {
	// Native error text can include non-UTF8 filesystem names. Keep wire text valid.
	msg := strings.ToValidUTF8(err.Error(), "�")
	msg = strings.ReplaceAll(msg, "\x00", "�")
	if len(msg) > 8192 {
		msg = msg[:8192]
		msg = strings.ToValidUTF8(msg, "�")
	}
	return AppendString(AppendU32(nil, code), msg)
}
func EncodeExit(reason uint32, code int, signal uint32) []byte {
	b := AppendU32(nil, reason)
	b = AppendU32(b, uint32(int32(code)))
	return AppendU32(b, signal)
}
