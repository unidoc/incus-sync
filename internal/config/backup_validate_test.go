package config

import (
	"strings"
	"testing"

	"github.com/unidoc/incus-sync/internal/model"
)

func TestBackupBlockValidation(t *testing.T) {
	cases := map[string]struct {
		b       *model.InstanceBackup
		wantErr string
	}{
		"ok policy":    {&model.InstanceBackup{Policy: "nightly"}, ""},
		"ok exclude":   {&model.InstanceBackup{Exclude: true}, ""},
		"ok absent":    {nil, ""},
		"both":         {&model.InstanceBackup{Policy: "x", Exclude: true}, "mutually exclusive"},
		"bad name":     {&model.InstanceBackup{Policy: "has space"}, "invalid backup.policy"},
		"bad name sym": {&model.InstanceBackup{Policy: "a/b"}, "invalid backup.policy"},
	}
	for name, c := range cases {
		f := &Fleet{Instances: map[string]model.Instance{"web": {Name: "web", Backup: c.b}}}
		err := f.validateInstances()
		switch {
		case c.wantErr == "" && err != nil:
			t.Errorf("%s: unexpected error %v", name, err)
		case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
			t.Errorf("%s: want error containing %q, got %v", name, c.wantErr, err)
		}
	}
}
