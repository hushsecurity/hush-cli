package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGatewayInstall(t *testing.T) {
	dir := t.TempDir()
	for _, env := range []string{"HOME", "USERPROFILE", "XDG_CONFIG_HOME", "APPDATA", "LOCALAPPDATA"} {
		t.Setenv(env, dir)
	}
	paths, _ := desktopConfigs()
	path := paths[0]
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	_ = os.WriteFile(path, []byte("\xef\xbb\xbf"+`{"mcpServers": {"other": {"command": "x"}}, "preferences": {"a": 1}}`), 0o600)

	if err := installGateway("claude-desktop", "https://gw.example/mcp", "hush"); err != nil {
		t.Fatal(err)
	}
	got := read(t, path)
	for _, want := range []string{`"hush": {`, `"https://gw.example/mcp"`, `"other"`, `"preferences"`} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %s: %s", want, got)
		}
	}
	if err := uninstallGateway("claude-desktop", "hush"); err != nil {
		t.Fatal(err)
	}
	if got := read(t, path); strings.Contains(got, `"hush"`) || !strings.Contains(got, `"other"`) {
		t.Fatalf("uninstall: %s", got)
	}

	for _, err := range []error{
		installGateway("cursor", "https://gw.example/mcp", "hush"),
		installGateway("claude-desktop", "http://gw.example/mcp", "hush"),
		installGateway("claude-desktop", "https://gw.example/mcp", "other"), // not ours
		uninstallGateway("claude-desktop", "other"),
	} {
		if err == nil {
			t.Fatal("want an error")
		}
	}
	if got := read(t, path); !strings.Contains(got, `"x"`) {
		t.Fatalf("changed another server: %s", got)
	}
	_ = os.WriteFile(path, []byte("null"), 0o600)
	if err := installGateway("claude-desktop", "https://gw.example/mcp", "hush"); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(path, []byte(`{"mcpServers": []}`), 0o600)
	if err := installGateway("claude-desktop", "https://gw.example/mcp", "hush"); err == nil {
		t.Fatal("overwrote a non-object mcpServers")
	}
}
