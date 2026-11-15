package cli

import (
	"os"
	"testing"

	"github.com/hushsecurity/hush-cli/internal/auth"
	"github.com/hushsecurity/hush-cli/internal/config"
)

func TestLogoutForgetsGateways(t *testing.T) {
	home := t.TempDir()
	for _, env := range []string{"HOME", "USERPROFILE", "XDG_CONFIG_HOME", "AppData"} {
		t.Setenv(env, home)
	}
	files := []string{auth.SessionFile, "gateways/gw.example_mcp.json"}
	for _, f := range files {
		if err := config.Save(f, map[string]string{"refresh_token": "rt"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := logout(); err != nil {
		t.Fatal(err)
	}
	config.ReleaseLock()
	for _, f := range files {
		path, _ := config.Path(f)
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("kept %s", f)
		}
	}
}
