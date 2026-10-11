package incus

import (
	"testing"

	"github.com/lxc/incus/v7/shared/api"

	"github.com/unidoc/incus-sync/internal/model"
)

func TestCreateRequestTypeFollowsTheDeclaredType(t *testing.T) {
	src := api.InstanceSource{Type: "image", Alias: "debian/13", Server: "https://images.linuxcontainers.org", Protocol: "simplestreams"}
	for _, tc := range []struct {
		typ  string
		want api.InstanceType
	}{
		{"", api.InstanceTypeContainer},
		{"container", api.InstanceTypeContainer},
		{"virtual-machine", api.InstanceTypeVM},
	} {
		req := instanceCreateRequest(model.Instance{Name: "x", Type: tc.typ}, src, []string{"default"}, nil, true)
		if req.Type != tc.want || req.Name != "x" || !req.Start || req.Source.Alias != "debian/13" {
			t.Errorf("type %q: %+v", tc.typ, req)
		}
	}
}

func TestCreateRequestCarriesTheBackupKeysForAVM(t *testing.T) {
	d := model.Instance{Name: "vm1", Type: "virtual-machine", Backup: &model.InstanceBackup{Policy: "nightly"}}
	req := instanceCreateRequest(d, api.InstanceSource{}, nil, nil, false)
	if req.Type != api.InstanceTypeVM || req.Config[model.BackupPolicyKey] != "nightly" || req.Start {
		t.Fatalf("%+v", req)
	}
}

func TestAdoptedVMKeepsItsType(t *testing.T) {
	vm := model.InstanceFromAPI(api.Instance{Name: "vm1", Type: "virtual-machine"})
	ct := model.InstanceFromAPI(api.Instance{Name: "c1", Type: "container"})
	if vm.Type != "virtual-machine" || ct.Type != "" {
		t.Fatalf("vm=%q container=%q (a container stays implicit)", vm.Type, ct.Type)
	}
}
