package config

// What counts as an empty backup: block, and a VM next to the directory `incus-sync create` scaffolds.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unidoc/incus-sync/internal/model"
)

func tDecode(t *testing.T, body string) string {
	path := filepath.Join(t.TempDir(), "instance.yaml")
	if err := os.WriteFile(path, []byte("instance: web\nproject: default\n"+body), 0o644); err != nil {
		t.Fatal(err)
	}
	var inst model.Instance
	if err := readYAMLFile(path, &inst); err != nil {
		return "decode-error"
	}
	set, unset, managed := inst.BackupConfig()
	return fmt.Sprintf("managed=%v|set=%v|unset=%v", managed, set, unset)
}

// docs/schema.md line 224 (head): "An empty `backup:` block (no policy, no exclude) removes both keys."
func TestEmptyBackupBlockSpellings(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"flow mapping {}", "backup: {}\n",
			"managed=true|set=map[]|unset=[user.backup.policy user.backup.exclude]"},
		// YAML null: the pointer stays nil, so this is "absent" (keys kept), whatever the docs say.
		{"bare key", "backup:\n",
			"managed=false|set=map[]|unset=[]"},
		{"policy line commented out", "backup:\n  # policy: nightly\n",
			"managed=false|set=map[]|unset=[]"},
		// A misspelt key must not silently turn into "remove both keys".
		{"misspelt key", "backup:\n  polcy: nightly\n",
			"decode-error"},
	} {
		got := tDecode(t, tc.body)
		t.Logf("%-28s %s", tc.name+":", got)
		if got != tc.want {
			t.Errorf("%s:\n got  %s\n want %s", tc.name, got, tc.want)
		}
	}
}

// cmd/incus-sync/cmd_create.go:52 always creates an empty files/ next to instance.yaml.
func TestScaffoldedDirectoryForAVM(t *testing.T) {
	validate := func(dir string) string {
		f := &Fleet{Instances: map[string]model.Instance{"web": {Name: "web", Type: model.InstanceTypeVM, SourceDir: dir}}}
		if err := f.validateInstances(); err != nil {
			return "refused"
		}
		return "ok"
	}
	scaffold := t.TempDir()
	if err := os.MkdirAll(filepath.Join(scaffold, "files"), 0o755); err != nil {
		t.Fatal(err)
	}
	populated := t.TempDir()
	if err := os.MkdirAll(filepath.Join(populated, "files", "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(populated, "files", "etc", "motd"), []byte("hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := strings.Join([]string{"empty-files=" + validate(scaffold), "populated-files=" + validate(populated)}, "|")
	t.Logf("%s", got)
	if want := "empty-files=ok|populated-files=refused"; got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}
