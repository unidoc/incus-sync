package incus

import (
	"testing"

	"github.com/lxc/incus/v7/shared/api"
	"github.com/unidoc/incus-sync/internal/config"
	"github.com/unidoc/incus-sync/internal/model"
)

func TestPlanDangerIngressWidening(t *testing.T) {
	// Simulate: live instance has ingress-default: reject, desired has allow.
	live := api.Instance{
		Name: "webapp",
		ExpandedDevices: map[string]map[string]string{
			"eth0": {"security.acls.default.ingress.action": "reject"},
		},
	}
	f := &config.Fleet{
		Instances: map[string]model.Instance{
			"webapp": {
				Name:           "webapp",
				IngressDefault: "allow",
			},
		},
	}
	p := &Plan{}
	planInstances(p, f, []api.Instance{live})

	found := false
	for _, e := range p.Entries {
		for _, d := range e.Dangers {
			if len(d) > 0 {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("expected danger for ingress widening, got entries: %+v", p.Entries)
	}
	if !p.HasDangers() {
		t.Error("HasDangers() should be true")
	}
}
