package incus

import (
	"testing"

	"github.com/lxc/incus/v7/shared/api"
	"github.com/unidoc/incus-sync/internal/config"
	"github.com/unidoc/incus-sync/internal/model"
)

// TestPlanDangerACLRemovalFullyEmptyInstance guards against the bug
// found in code review: an instance file emptied down to nothing
// (no acls, no ingress/egress-default — flat form's "identity only"
// shape) made EffectiveDevices() return nil, which made planInstances
// skip eth0 for this instance ENTIRELY. The container's live ACLs were
// silently left in place forever, and the "loses all ACLs" danger gate
// never even ran. See also TestDiffDeviceKeysDetectsRemoval and
// TestUnsetDeviceKeys for the lower-level fix this depends on.
func TestPlanDangerACLRemovalFullyEmptyInstance(t *testing.T) {
	live := api.Instance{
		Name: "webapp",
		ExpandedDevices: map[string]map[string]string{
			"eth0": {"security.acls": "some-acl"},
		},
	}
	f := &config.Fleet{
		Instances: map[string]model.Instance{
			// Flat form, fully empty: no AttachedACLs, no
			// ingress/egress-default. This is the exact shape that
			// made EffectiveDevices() return nil.
			"webapp": {Name: "webapp"},
		},
	}
	p := &Plan{}
	planInstances(p, f, []api.Instance{live})

	var entry *PlanEntry
	for i := range p.Entries {
		if p.Entries[i].Name == "webapp.eth0" {
			entry = &p.Entries[i]
		}
	}
	if entry == nil {
		t.Fatalf("expected a webapp.eth0 plan entry (instance must not be skipped entirely); got entries: %+v", p.Entries)
	}
	if entry.Action != ActionUpdate {
		t.Errorf("expected ActionUpdate (ACL removal is a real change), got %v", entry.Action)
	}
	found := false
	for _, d := range entry.Dangers {
		if len(d) > 0 {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a danger for removing all attached ACLs, got entry: %+v", entry)
	}
	if !p.HasDangers() {
		t.Error("HasDangers() should be true")
	}
}

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
