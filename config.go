package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// Session is the saved sign-in.
type Session struct {
	API          string `json:"api"`
	ClientID     string `json:"client_id"`
	RedirectURI  string `json:"redirect_uri"`
	RefreshToken string `json:"refresh_token,omitempty"`
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
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
