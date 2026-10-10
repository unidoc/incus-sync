package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unidoc/incus-sync/internal/model"
)

func TestInstanceTypeValidation(t *testing.T) {
	cases := map[string]struct {
		inst    model.Instance
		wantErr string
	}{
		"default is a container": {model.Instance{Name: "web"}, ""},
		"container":              {model.Instance{Name: "web", Type: "container"}, ""},
		"vm":                     {model.Instance{Name: "web", Type: "virtual-machine"}, ""},
		"vm with a backup block": {model.Instance{Name: "web", Type: "virtual-machine", Backup: &model.InstanceBackup{Policy: "nightly"}}, ""},
		"unknown type":           {model.Instance{Name: "web", Type: "vm"}, "invalid type"},
		"vm provision":           {model.Instance{Name: "web", Type: "virtual-machine", Provision: &model.ProvisionSpec{}}, "not supported for virtual machines"},
		"container provision":    {model.Instance{Name: "web", Provision: &model.ProvisionSpec{}}, ""},
	}
	for name, c := range cases {
		f := &Fleet{Instances: map[string]model.Instance{"web": c.inst}}
		err := f.validateInstances()
		switch {
		case c.wantErr == "" && err != nil:
			t.Errorf("%s: unexpected error %v", name, err)
		case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
			t.Errorf("%s: want error containing %q, got %v", name, c.wantErr, err)
		}
	}
}

// before.sh, after.sh and files/ next to instance.yaml run inside the guest at create time; a VM has no agent yet.
func TestVMRefusesProvisioningFilesInItsDirectory(t *testing.T) {
	for _, f := range []string{"before.sh", "after.sh", "files"} {
		dir := t.TempDir()
		p := filepath.Join(dir, f)
		if f == "files" {
			if err := os.Mkdir(p, 0o755); err != nil {
				t.Fatal(err)
			}
		} else if err := os.WriteFile(p, []byte("true\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		vm := &Fleet{Instances: map[string]model.Instance{"web": {Name: "web", Type: "virtual-machine", SourceDir: dir}}}
		if err := vm.validateInstances(); err == nil || !strings.Contains(err.Error(), f) {
			t.Errorf("%s next to a VM: %v", f, err)
		}
		ct := &Fleet{Instances: map[string]model.Instance{"web": {Name: "web", SourceDir: dir}}}
		if err := ct.validateInstances(); err != nil {
			t.Errorf("%s next to a container must stay allowed: %v", f, err)
		}
	}
	vm := &Fleet{Instances: map[string]model.Instance{"web": {Name: "web", Type: "virtual-machine", SourceDir: t.TempDir()}}}
	if err := vm.validateInstances(); err != nil {
		t.Errorf("an empty instance directory is fine for a VM: %v", err)
	}
}
