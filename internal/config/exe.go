package config

import (
	"os"
	"os/exec"
	"path/filepath"
)

// Executable is this binary's full path, preferring its PATH entry (e.g.
// Homebrew's link), which survives upgrades.
func Executable() string {
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

func sameFile(a, b string) bool {
	fa, errA := os.Stat(a)
	fb, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(fa, fb)
}
