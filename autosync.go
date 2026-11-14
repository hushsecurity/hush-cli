package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

const syncArgs = "skills sync --quiet"

// autosync turns on or off a Claude Code hook that syncs skills whenever a
// session starts, or with no argument says whether it's on.
func autosync(arg string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	path := filepath.Join(home, ".claude", "settings.json")
	changed, err := editJSON(path, func(settings map[string]any) (bool, error) {
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

// hushExe is this binary's full path, preferring its PATH entry (e.g.
// Homebrew's link), which survives upgrades.
func hushExe() string {
	exe, err := os.Executable()
	if err != nil {
		return "hush"
	}
	if p, err := exec.LookPath("hush"); err == nil {
		if abs, err := filepath.Abs(p); err == nil && sameFile(abs, exe) {
			exe = abs
		}
	}
	return exe
}

// hushPath is hushExe for a hook command.
func hushPath() string {
	exe := filepath.ToSlash(hushExe()) // Claude Code runs Windows hooks in Git Bash
	if strings.ContainsAny(exe, ` '`) {
		return strconv.Quote(exe)
	}
	return exe
}

func sameFile(a, b string) bool {
	fa, errA := os.Stat(a)
	fb, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(fa, fb)
}
