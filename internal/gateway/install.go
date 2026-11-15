package gateway

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/hushsecurity/hush-cli/internal/config"
)

// Clients are the agents Install can set up.
var Clients = []string{"claude-desktop"}

func checkClient(client string) error {
	if client != "claude-desktop" {
		return fmt.Errorf("unknown client %q (supported: %v)", client, Clients)
	}
	if os.Geteuid() == 0 { // root's config isn't the user's (-1 on Windows)
		return errors.New("run it as the user, not root (e.g. sudo -H -u <user>)")
	}
	return nil
}

// Install adds the gateway, served by gateway proxy, to Claude Desktop.
func Install(client, gw, name string) error {
	if err := checkClient(client); err != nil {
		return err
	}
	if err := checkGatewayURL(gw); err != nil {
		return err
	}
	server := map[string]any{"command": config.Executable(), "args": []string{"gateway", "proxy", gw}}
	return editDesktopServers(func(servers map[string]any) (bool, error) {
		if old, ok := servers[name]; ok && !isProxy(old) {
			return false, fmt.Errorf("it already has a server named %s; pick another --name", name)
		}
		servers[name] = server
		return true, nil
	}, "Added "+name+" to")
}

func Uninstall(client, name string) error {
	if err := checkClient(client); err != nil {
		return err
	}
	return editDesktopServers(func(servers map[string]any) (bool, error) {
		old, ok := servers[name]
		if ok && !isProxy(old) {
			return false, fmt.Errorf("its %s server wasn't added by hush", name)
		}
		delete(servers, name)
		return ok, nil
	}, "Removed "+name+" from")
}

// isProxy says whether a server runs gateway proxy, i.e. install added it.
func isProxy(server any) bool {
	s, _ := server.(map[string]any)
	args, _ := s["args"].([]any)
	return len(args) >= 2 && args[0] == "gateway" && args[1] == "proxy"
}

func editDesktopServers(edit func(map[string]any) (bool, error), done string) error {
	paths, err := desktopConfigs()
	if err != nil {
		return err
	}
	anyChanged := false
	for _, path := range paths {
		changed, err := config.EditJSON(path, func(cfg map[string]any) (bool, error) {
			servers, ok := cfg["mcpServers"].(map[string]any)
			if !ok && cfg["mcpServers"] != nil {
				return false, errors.New("its mcpServers isn't an object")
			}
			if servers == nil {
				servers = map[string]any{}
			}
			cfg["mcpServers"] = servers
			return edit(servers)
		})
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if changed {
			fmt.Println(done, path)
			anyChanged = true
		}
	}
	if anyChanged {
		fmt.Println("Restart Claude Desktop to load the change.")
	} else {
		fmt.Println("No change to", strings.Join(paths, ", "))
	}
	return nil
}

// desktopConfigs are Claude Desktop's config files. The Microsoft Store build
// keeps its own, under LocalAppData.
func desktopConfigs() ([]string, error) {
	const file = "claude_desktop_config.json"
	if runtime.GOOS == "windows" {
		dirs, _ := filepath.Glob(filepath.Join(os.Getenv("LOCALAPPDATA"), "Claude-Data", "claude_*"))
		for i := range dirs {
			dirs[i] = filepath.Join(dirs[i], file)
		}
		if len(dirs) > 0 {
			return dirs, nil
		}
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return nil, err
	}
	return []string{filepath.Join(dir, "Claude", file)}, nil
}
