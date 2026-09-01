// Package gitcheck performs best-effort git hygiene checks on the fleet
// repo before sync --apply. Skipped silently if the repo has no git dir
// or the git binary isn't on PATH — the tool doesn't require git.
package gitcheck

import (
	"bytes"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// Status is a shallow read of the fleet dir's git state.
type Status struct {
	IsRepo      bool
	Dirty       bool // uncommitted changes
	BehindCount int  // commits upstream has ahead of us
	AheadCount  int  // commits we have ahead of upstream
	Note        string
}

// Inspect runs `git` inside configDir and returns a Status. Any error
// short-circuits into Status.Note without a hard failure — the tool
// treats git as a courtesy, not a requirement.
func Inspect(configDir string) Status {
	if !isRepo(configDir) {
		return Status{Note: "not a git repository (skipping git checks)"}
	}
	s := Status{IsRepo: true}

	// Dirty check: any uncommitted change including untracked.
	if out, err := gitCmd(configDir, "status", "--porcelain"); err == nil {
		if strings.TrimSpace(string(out)) != "" {
			s.Dirty = true
		}
	}

	// Upstream check: only meaningful if a tracking branch is set.
	if _, err := gitCmd(configDir, "rev-parse", "--abbrev-ref", "@{u}"); err == nil {
		if out, err := gitCmd(configDir, "rev-list", "--left-right", "--count", "@{u}...HEAD"); err == nil {
			parts := strings.Fields(strings.TrimSpace(string(out)))
			if len(parts) == 2 {
				_, _ = fmt.Sscanf(parts[0], "%d", &s.BehindCount)
				_, _ = fmt.Sscanf(parts[1], "%d", &s.AheadCount)
			}
		}
	} else {
		s.Note = "no upstream tracking branch"
	}
	return s
}

// Warnings returns human-readable strings for anything the operator
// should notice before applying. Empty slice = clean.
func (s Status) Warnings() []string {
	var out []string
	if !s.IsRepo {
		return nil
	}
	if s.Dirty {
		out = append(out, "config repo has uncommitted changes (git status --porcelain is non-empty)")
	}
	if s.BehindCount > 0 {
		out = append(out, fmt.Sprintf("config repo is %d commit(s) behind upstream — consider `git pull` first", s.BehindCount))
	}
	return out
}

func isRepo(configDir string) bool {
	_, err := gitCmd(configDir, "rev-parse", "--is-inside-work-tree")
	return err == nil
}

func gitCmd(dir string, args ...string) ([]byte, error) {
	if _, err := exec.LookPath("git"); err != nil {
		return nil, err
	}
	full := append([]string{"-C", filepath.Clean(dir)}, args...)
	var stdout, stderr bytes.Buffer
	c := exec.Command("git", full...)
	c.Stdout = &stdout
	c.Stderr = &stderr
	if err := c.Run(); err != nil {
		return nil, fmt.Errorf("git %s: %w (%s)", strings.Join(full, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}
