package skills

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/hushsecurity/hush-cli/internal/config"
)

const syncArgs = "skills sync --quiet"

// Autosync turns on or off a Claude Code hook that syncs skills whenever a
// session starts, or with no argument says whether it's on.
func Autosync(arg string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	path := filepath.Join(home, ".claude", "settings.json")
	changed, err := config.EditJSON(path, func(settings map[string]any) (bool, error) {
		hooks, _ := settings["hooks"].(map[string]any)
		if hooks == nil {
			hooks = map[string]any{}
		}
		starts, _ := hooks["SessionStart"].([]any)
		on := slices.ContainsFunc(starts, isSyncHook)

		switch arg {
		case "":
			fmt.Println(map[bool]string{true: "on", false: "off"}[on])
			return false, nil
		case "on":
			if on {
				return false, nil
			}
			starts = append(starts, map[string]any{
				"matcher": "startup",
				"hooks": []any{map[string]any{
					"type": "command", "command": hushPath() + " " + syncArgs, "timeout": 120,
				}},
			})
		case "off":
			starts = slices.DeleteFunc(starts, isSyncHook)
		default:
			return false, errors.New("usage: hush skills autosync [on|off]")
		}

		if len(starts) > 0 {
			hooks["SessionStart"] = starts
		} else {
			delete(hooks, "SessionStart")
		}
		if len(hooks) > 0 {
			settings["hooks"] = hooks
		} else {
			delete(settings, "hooks")
		}
		return true, nil
	})
	if err != nil || !changed {
		return err
	}
	fmt.Printf("Turned skills autosync %s for Claude Code\n", arg)
	return nil
}

func isSyncHook(entry any) bool {
	e, _ := entry.(map[string]any)
	hooks, _ := e["hooks"].([]any)
	return slices.ContainsFunc(hooks, func(h any) bool {
		hook, _ := h.(map[string]any)
		cmd, _ := hook["command"].(string)
		return strings.HasSuffix(cmd, syncArgs)
	})
}

// hushPath is the executable's path for a hook command.
func hushPath() string {
	exe := filepath.ToSlash(config.Executable()) // Claude Code runs Windows hooks in Git Bash
	if strings.ContainsAny(exe, ` '`) {
		return strconv.Quote(exe)
	}
	return exe
}
