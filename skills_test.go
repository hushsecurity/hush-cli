package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeAPI serves the token endpoint and the user's skills.
func fakeAPI(t *testing.T, skills *[]Skill, files map[string]string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agents/oauth/token":
			_ = json.NewEncoder(w).Encode(token{AccessToken: "at", RefreshToken: "rt2"})
		case "/v1/skills/me":
			_ = json.NewEncoder(w).Encode(*skills)
		default:
			if !strings.HasPrefix(r.URL.Path, "/v1/skills/me/") {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write([]byte(files[path.Base(r.URL.Path)]))
		}
	}))
	t.Cleanup(srv.Close)
	home := t.TempDir()
	for _, env := range []string{"HOME", "USERPROFILE", "XDG_CONFIG_HOME", "AppData"} {
		t.Setenv(env, home)
	}
	if err := save(sessionFile, Session{API: srv.URL, RefreshToken: "rt"}); err != nil {
		t.Fatal(err)
	}
}

func skill(name string, version int, files map[string]string, body string) Skill {
	sum := sha256.Sum256([]byte(body))
	digest := hex.EncodeToString(sum[:])
	files[digest] = body
	s := Skill{ID: "skl-" + name, Name: name, Version: version}
	s.Files = []SkillFile{{"SKILL.md", digest, len(body)}}
	return s
}

func read(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}

func TestSync(t *testing.T) {
	files := map[string]string{}
	skills := []Skill{skill("one", 1, files, "v1")}
	fakeAPI(t, &skills, files)
	home, _ := os.UserHomeDir()
	shared := filepath.Join(home, ".agents", "skills")
	claude := filepath.Join(home, ".claude", "skills")
	other := filepath.Join(claude, "mine", "SKILL.md")
	_ = os.MkdirAll(filepath.Dir(other), 0o755)
	_ = os.WriteFile(other, []byte("not hush's"), 0o644)

	if err := syncSkills(""); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{shared, claude} {
		if got := read(t, filepath.Join(dir, "one", "SKILL.md")); got != "v1" {
			t.Fatalf("installed %q in %s", got, dir)
		}
	}

	// A deleted skill comes back.
	_ = os.RemoveAll(filepath.Join(shared, "one"))
	if err := syncSkills(""); err != nil {
		t.Fatal(err)
	}
	if got := read(t, filepath.Join(claude, "one", "SKILL.md")); got != "v1" {
		t.Fatalf("restored %q", got)
	}

	// A new version replaces it; a folder hush didn't install is left alone.
	skills = []Skill{skill("one", 2, files, "v2"), skill("mine", 1, files, "hush's")}
	if err := syncSkills(""); err == nil {
		t.Fatal("linked over a skill hush didn't install")
	}
	if got := read(t, filepath.Join(claude, "one", "SKILL.md")); got != "v2" {
		t.Fatalf("updated %q", got)
	}
	if got := read(t, other); got != "not hush's" {
		t.Fatalf("overwrote a skill hush didn't install: %q", got)
	}

	// Unassigned skills are removed.
	skills = nil
	if err := syncSkills(""); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{shared, claude} {
		if _, err := os.Lstat(filepath.Join(dir, "one")); !os.IsNotExist(err) {
			t.Fatalf("kept an unassigned skill in %s", dir)
		}
	}
	if read(t, other) == "" {
		t.Fatal("removed a skill hush didn't install")
	}
}

func TestSyncRefusesBadFiles(t *testing.T) {
	files := map[string]string{}
	bad := skill("bad", 1, files, "body")
	for digest := range files {
		files[digest] = "tampered"
	}
	escape := skill("escape", 1, files, "x")
	escape.Files[0].Path = "../escape.md"
	for _, s := range []Skill{bad, escape} {
		skills := []Skill{s}
		fakeAPI(t, &skills, files)
		if err := syncSkills(""); err == nil {
			t.Fatalf("installed %s", s.Name)
		}
	}
}

func TestRemoveAndAdd(t *testing.T) {
	files := map[string]string{}
	skills := []Skill{skill("one", 1, files, "v1")}
	fakeAPI(t, &skills, files)
	home, _ := os.UserHomeDir()
	installed := filepath.Join(home, ".agents", "skills", "one", "SKILL.md")

	if err := syncSkills(""); err != nil {
		t.Fatal(err)
	}
	if err := removeSkill("one"); err != nil {
		t.Fatal(err)
	}
	if err := syncSkills(""); err != nil {
		t.Fatal(err)
	}
	if read(t, installed) != "" {
		t.Fatal("sync reinstalled a removed skill")
	}
	if err := syncSkills("one"); err != nil { // hush skills add one
		t.Fatal(err)
	}
	if got := read(t, installed); got != "v1" {
		t.Fatalf("added %q", got)
	}
}

func TestAutosync(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	path := filepath.Join(home, ".claude", "settings.json")
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	other := `{"model": "opus", "hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "echo hi"}]}]}}`
	_ = os.WriteFile(path, []byte(other), 0o600)

	if err := autosync("on"); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	if err := autosync("on"); err != nil { // no duplicate
		t.Fatal(err)
	}
	got := read(t, path)
	if strings.Count(got, syncArgs) != 1 || !strings.Contains(got, "echo hi") || !strings.Contains(got, "opus") {
		t.Fatalf("on: %s", got)
	}
	if err := autosync("off"); err != nil {
		t.Fatal(err)
	}
	got = read(t, path)
	if strings.Contains(got, syncArgs) || !strings.Contains(got, "echo hi") {
		t.Fatalf("off: %s", got)
	}
}
