package cli

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
)

type account struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Password string `json:"password"`
	Email    string `json:"email,omitempty"`
	Token    string `json:"token"`
}
type config struct {
	Version int     `json:"version"`
	API     string  `json:"api"`
	CAFile  string  `json:"ca_file,omitempty"`
	Account account `json:"account"`
}

func configPath(explicit string) (string, error) {
	if explicit != "" {
		return filepath.Abs(explicit)
	}
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		if runtime.GOOS == "ohos" {
			return "", errors.New("XDG_CONFIG_HOME is required on OHOS; HOME cannot protect credentials")
		}
		var err error
		base, err = os.UserConfigDir()
		if err != nil {
			return "", err
		}
	}
	if !filepath.IsAbs(base) {
		return "", errors.New("XDG_CONFIG_HOME must be absolute")
	}
	return filepath.Join(base, "oheco-broker", "account.json"), nil
}
func privateDirectory(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("credential parent must be a real private directory")
	}
	if info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("credential directory is not private (mode %03o); use a private XDG_CONFIG_HOME", info.Mode().Perm())
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Uid != uint32(os.Getuid()) {
		return errors.New("credential directory belongs to another user")
	}
	return nil
}
func loadConfig(path string) (config, error) {
	var cfg config
	info, err := os.Lstat(path)
	if err != nil {
		return cfg, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return cfg, errors.New("credential file must be a private regular file")
	}
	if info.Size() > 65536 {
		return cfg, errors.New("credential file too large")
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Uid != uint32(os.Getuid()) {
		return cfg, errors.New("credential file belongs to another user")
	}
	if err = privateDirectory(path); err != nil {
		return cfg, err
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return cfg, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return cfg, err
	}
	if !opened.Mode().IsRegular() || opened.Mode().Perm()&0077 != 0 || opened.Size() > 65536 {
		return cfg, errors.New("opened credential file is unsafe")
	}
	if st, ok := opened.Sys().(*syscall.Stat_t); ok && st.Uid != uint32(os.Getuid()) {
		return cfg, errors.New("opened credential file belongs to another user")
	}
	decoder := json.NewDecoder(io.LimitReader(file, 65537))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&cfg); err != nil {
		return cfg, err
	}
	var tail any
	if err = decoder.Decode(&tail); err != io.EOF {
		return cfg, errors.New("credential file contains trailing data")
	}
	if cfg.Version != 1 || cfg.API == "" {
		return cfg, errors.New("unsupported or incomplete credential configuration")
	}
	return cfg, nil
}
func saveConfig(path string, cfg config) error {
	if err := privateDirectory(path); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return errors.New("refusing to replace unsafe credential file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	file, err := os.CreateTemp(filepath.Dir(path), ".account-*")
	if err != nil {
		return err
	}
	temp := file.Name()
	defer os.Remove(temp)
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(raw)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	info, err := os.Stat(temp)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0077 != 0 {
		return errors.New("filesystem cannot protect credentials; refusing to persist")
	}
	if err = os.Rename(temp, path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func generatedCredentials() (string, string, error) {
	var id [16]byte
	var password [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", "", err
	}
	if _, err := rand.Read(password[:]); err != nil {
		return "", "", err
	}
	id[6] = (id[6] & 15) | 64
	id[8] = (id[8] & 63) | 128
	h := hex.EncodeToString(id[:])
	return "tenant-" + h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], hex.EncodeToString(password[:]), nil
}
