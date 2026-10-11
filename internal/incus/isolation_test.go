package incus

import (
	"testing"

	"github.com/lxc/incus/v7/shared/api"

	"github.com/unidoc/incus-sync/internal/config"
)

func violations(p *Plan) []PlanEntry {
	var out []PlanEntry
	for _, e := range p.Entries {
		if len(e.Dangers) > 0 {
			out = append(out, e)
		}
	}
	return out
}

// Nesting inside an unprivileged container is allowed; privileged containers and
// non-isolated idmaps are still refused.
func TestIsolationPolicyAllowsNestingAndBansPrivileged(t *testing.T) {
	fleet := &config.Fleet{}
	for _, tc := range []struct {
		cfg  map[string]string
		bad  bool
		name string
	}{
		{map[string]string{"security.nesting": "true"}, false, "nesting"},
		{map[string]string{"security.nesting": "true", "security.privileged": "true"}, true, "nesting + privileged"},
		{map[string]string{"security.privileged": "true"}, true, "privileged"},
		{map[string]string{"security.idmap.isolated": "false"}, true, "shared idmap"},
	} {
		p := &Plan{}
		planInstances(p, fleet, []api.Instance{liveInst("c1", tc.cfg)})
		if got := len(violations(p)) > 0; got != tc.bad {
			t.Errorf("%s: violation=%v, want %v: %+v", tc.name, got, tc.bad, p.Entries)
		}
	}
}

// --force applies a plan that holds a policy-violation report. The report has no executor and used to
// be called anyway (nil function panic).
func TestApplyWithForceSkipsPolicyViolationReports(t *testing.T) {
	p := &Plan{}
	planInstances(p, &config.Fleet{}, []api.Instance{liveInst("c1", map[string]string{"security.privileged": "true"})})
	if len(violations(p)) == 0 {
		t.Fatal("no violation reported")
	}
	if err := p.Apply(nil, false); err != nil {
		t.Fatalf("apply: %v", err)
	}
}
