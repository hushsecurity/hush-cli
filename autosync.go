package main

import (
	"encoding/json"
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
	settings := map[string]any{}
	data, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(data, &settings); err != nil {
			return fmt.Errorf("can't read %s: %w", path, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	hooks, _ := settings["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
	}
	starts, _ := hooks["SessionStart"].([]any)
	on := slices.ContainsFunc(starts, isSyncHook)

	switch arg {
	case "":
		fmt.Println(map[bool]string{true: "on", false: "off"}[on])
		return nil
	case "on":
		if on {
			return nil
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
		return errors.New("usage: hush skills autosync [on|off]")
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
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if real, err := filepath.EvalSymlinks(path); err == nil {
		path = real // keep a dotfiles link
	}
	perm := os.FileMode(0o644)
	if fi, err := os.Stat(path); err == nil {
		perm = fi.Mode().Perm() // e.g. 0600 for one holding secrets
	}
	if err := writeJSON(path, settings, perm); err != nil {
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

// hushPath is this binary's full path for the hook, preferring its PATH
// entry (e.g. Homebrew's link), which survives upgrades.
func hushPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "hush"
	}
	if p, err := exec.LookPath("hush"); err == nil {
		if abs, err := filepath.Abs(p); err == nil && sameFile(abs, exe) {
			exe = abs
		}
	}
	exe = filepath.ToSlash(exe) // Claude Code runs Windows hooks in Git Bash
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
