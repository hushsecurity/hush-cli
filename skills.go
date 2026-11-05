package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const manifestFile = "skills.json"

// Skills are kept once in ~/.agents/skills, which Codex, Cursor and most
// agents read; clients that don't get a link to them in their own folder.
const sharedDir = ".agents/skills"

var linkedClients = []struct{ name, dir string }{
	{".claude", ".claude/skills"}, // Claude Code
}

type Skill struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Version     int         `json:"version"`
	Files       []SkillFile `json:"files"`
}

type SkillFile struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
	Size   int    `json:"size"`
}

// Installed is a skill sync installed, and the client folders it linked it into.
type Installed struct {
	ID      string   `json:"id"`
	Version int      `json:"version"`
	Links   []string `json:"links,omitempty"`
}

func fetchSkills(c *Client) ([]Skill, error) {
	var skills []Skill
	return skills, c.getJSON("/v1/skills/me", &skills)
}

type skillRow struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Version     int    `json:"version,omitempty"`
	Installed   int    `json:"installed_version,omitempty"`
	State       string `json:"state"`
}

func listSkills(asJSON bool) error {
	c, err := signedIn()
	if err != nil {
		return err
	}
	skills, err := fetchSkills(c)
	if err != nil {
		return err
	}
	manifest := map[string]Installed{}
	if err := load(manifestFile, &manifest); err != nil {
		return err
	}
	rows := []skillRow{}
	for _, s := range skills {
		inst, ok := manifest[s.Name]
		state := "installed"
		if !ok {
			state = "not installed"
		} else if inst.Version != s.Version {
			state = fmt.Sprintf("update available (v%d installed)", inst.Version)
		}
		rows = append(rows, skillRow{s.Name, s.Description, s.Version, inst.Version, state})
	}
	for _, name := range slices.Sorted(maps.Keys(manifest)) {
		if !hasSkill(skills, name) {
			rows = append(rows, skillRow{Name: name, Installed: manifest[name].Version, State: "no longer assigned"})
		}
	}

	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rows)
	}
	if len(rows) == 0 {
		fmt.Println("No skills are assigned to you.")
	}
	for _, r := range rows {
		fmt.Printf("%s  v%d  %s\n", r.Name, max(r.Version, r.Installed), r.State)
		if r.Description != "" {
			fmt.Printf("  %s\n", truncate(r.Description, 100))
		}
	}
	return nil
}

func truncate(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

// showSkill prints a skill's details and its SKILL.md.
func showSkill(name string) error {
	c, err := signedIn()
	if err != nil {
		return err
	}
	skills, err := fetchSkills(c)
	if err != nil {
		return err
	}
	i := slices.IndexFunc(skills, func(s Skill) bool { return s.Name == name })
	if i < 0 {
		return fmt.Errorf("skill %q is not assigned to you", name)
	}
	s := skills[i]
	fmt.Printf("%s v%d\n\n%s\n\nFiles:\n", s.Name, s.Version, s.Description)
	var skillMD []byte
	for _, f := range s.Files {
		fmt.Printf("  %s (%d bytes)\n", f.Path, f.Size)
		if f.Path == "SKILL.md" {
			if skillMD, err = fetchFile(c, s, f.Digest); err != nil {
				return err
			}
		}
	}
	fmt.Printf("\n%s", skillMD)
	return nil
}

func syncSkills(only string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	shared := filepath.Join(home, sharedDir)
	var linkDirs []string
	for _, lc := range linkedClients {
		if _, err := os.Stat(filepath.Join(home, lc.name)); err == nil {
			linkDirs = append(linkDirs, filepath.Join(home, lc.dir))
		}
	}

	c, err := signedIn()
	if err != nil {
		return err
	}
	skills, err := fetchSkills(c)
	if err != nil {
		return err
	}
	if only != "" && !hasSkill(skills, only) {
		return fmt.Errorf("skill %q is not assigned to you", only)
	}

	manifest := map[string]Installed{}
	if err := load(manifestFile, &manifest); err != nil {
		return err
	}
	failed := 0
	for _, s := range skills {
		if only != "" && s.Name != only {
			continue
		}
		changed, err := installSkill(c, shared, s, manifest)
		for _, dir := range linkDirs {
			if err == nil {
				err = linkSkill(shared, dir, s.Name, changed, manifest)
			}
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Couldn't install %s: %v\n", s.Name, err)
			failed++
		}
	}
	if only == "" {
		removeUnassigned(shared, skills, manifest)
	}
	if err := save(manifestFile, manifest); err != nil {
		return err
	}
	if failed > 0 {
		return fmt.Errorf("%d skill(s) failed to install", failed)
	}
	return nil
}

func hasSkill(skills []Skill, name string) bool {
	for _, s := range skills {
		if s.Name == name {
			return true
		}
	}
	return false
}

// installSkill puts the skill in the shared folder; it reports whether it
// changed anything.
func installSkill(c *Client, dir string, s Skill, manifest map[string]Installed) (bool, error) {
	if !filepath.IsLocal(s.Name) || strings.ContainsAny(s.Name, `/\`) || strings.HasPrefix(s.Name, ".") {
		return false, fmt.Errorf("unsafe name %q", s.Name)
	}
	dest := filepath.Join(dir, s.Name)
	prev, ours := manifest[s.Name]
	_, statErr := os.Stat(dest)
	if ours && prev.ID == s.ID && prev.Version == s.Version && statErr == nil {
		return false, nil
	}
	if statErr == nil && !ours {
		return false, fmt.Errorf("%s exists and wasn't installed by hush", dest)
	}

	// Download into a temp folder next to it, then swap it in.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, err
	}
	tmp, err := os.MkdirTemp(dir, ".hush-"+s.Name+"-")
	if err != nil {
		return false, err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	for _, f := range s.Files {
		if err := download(c, s, f.Path, f.Digest, tmp); err != nil {
			return false, err
		}
	}
	if err := os.RemoveAll(dest); err != nil {
		return false, err
	}
	if err := os.Rename(tmp, dest); err != nil {
		return false, err
	}
	manifest[s.Name] = Installed{s.ID, s.Version, prev.Links}
	fmt.Printf("Installed %s v%d in %s\n", s.Name, s.Version, dir)
	return true, nil
}

// linkSkill links a client's folder to the shared skill, or copies it where
// links aren't allowed (e.g. Windows without developer mode).
func linkSkill(shared, dir, name string, changed bool, manifest map[string]Installed) error {
	inst := manifest[name]
	ours := slices.Contains(inst.Links, dir)
	dest := filepath.Join(dir, name)
	if fi, err := os.Lstat(dest); err == nil {
		if !ours {
			return fmt.Errorf("%s exists and wasn't installed by hush", dest)
		}
		if fi.Mode()&fs.ModeSymlink != 0 || !changed {
			return nil // a link follows the shared copy; a copy is current
		}
		if err := os.RemoveAll(dest); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	src := filepath.Join(shared, name)
	if err := os.Symlink(src, dest); err != nil {
		if err := os.CopyFS(dest, os.DirFS(src)); err != nil {
			return err
		}
	}
	if !ours {
		inst.Links = append(inst.Links, dir)
		manifest[name] = inst
	}
	return nil
}

func download(c *Client, s Skill, path, digest, root string) error {
	rel := filepath.FromSlash(path)
	if !filepath.IsLocal(rel) {
		return fmt.Errorf("unsafe file path %q", path)
	}
	data, err := fetchFile(c, s, digest)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	dest := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	return os.WriteFile(dest, data, 0o644)
}

// fetchFile downloads a skill file and checks it against its digest.
func fetchFile(c *Client, s Skill, digest string) ([]byte, error) {
	resp, err := c.get(fmt.Sprintf("/v1/skills/me/%s/files/%s", s.ID, digest))
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if err := checkStatus(resp); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != digest {
		return nil, errors.New("digest mismatch")
	}
	return data, nil
}

// removeUnassigned deletes the skills sync installed that are no longer yours.
func removeUnassigned(shared string, skills []Skill, manifest map[string]Installed) {
	for name, inst := range manifest {
		if hasSkill(skills, name) {
			continue
		}
		var err error
		for _, dir := range append(inst.Links, shared) {
			if e := os.RemoveAll(filepath.Join(dir, name)); e != nil {
				err = e
			}
		}
		if err != nil {
			fmt.Printf("Couldn't remove %s: %v\n", name, err)
			continue
		}
		delete(manifest, name)
		fmt.Printf("Removed %s\n", name)
	}
}
