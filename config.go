package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Session is the saved sign-in.
type Session struct {
	API          string `json:"api"`
	ClientID     string `json:"client_id"`
	RedirectURI  string `json:"redirect_uri"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Org          string `json:"org,omitempty"` // the short name, when login was given it
}

func configPath(name string) (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "hush", name), nil
}

// load reads a JSON config file into v; a missing file leaves v as is.
func load(name string, v any) error {
	path, err := configPath(name)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// save writes v as JSON, readable only by the user (it may hold a token).
func save(name string, v any) error {
	path, err := configPath(name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return writeJSON(path, v, 0o600)
}

// writeJSON replaces a file with v as indented JSON, all at once.
func writeJSON(path string, v any, perm os.FileMode) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

var (
	lockMu   sync.Mutex
	lockPath string // set while this run holds the lock
)

// lockSession keeps hush runs (e.g. autosync in two new sessions) from
// using the single-use refresh token at once. It's released on exit, even
// when interrupted; one older than any run takes is left from a crash.
func lockSession() error {
	if lockPath != "" {
		return nil
	}
	path, err := configPath("lock")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(200 * time.Millisecond) {
		lockMu.Lock() // so a signal can't land between taking and recording it
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_ = f.Close()
			lockPath = path
		}
		lockMu.Unlock()
		if err == nil {
			return nil
		}
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		if fi, err := os.Stat(path); err == nil && time.Since(fi.ModTime()) > 2*time.Minute {
			_ = os.Remove(path)
		} else if time.Now().After(deadline) {
			return errors.New("another hush command is running")
		}
	}
}

// touchLock shows a long run is still alive, so others don't break its lock.
func touchLock() {
	if lockPath != "" {
		now := time.Now()
		_ = os.Chtimes(lockPath, now, now)
	}
}

func releaseLock() {
	lockMu.Lock()
	defer lockMu.Unlock()
	if lockPath != "" {
		_ = os.Remove(lockPath)
		lockPath = ""
	}
}
