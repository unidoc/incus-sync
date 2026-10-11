package incus

// The backup block against a fake server that keeps ExpandedConfig = profile config overlaid by local config,
// and a transplant of incus-backup's selection rule (internal/client/engine/discover.go Resolve): exclude wins,
// then an explicit user.backup.policy, both read from the EFFECTIVE config.

import (
	"context"
	"fmt"
	"strings"
	"testing"

	incusclient "github.com/lxc/incus/v7/client"
	"github.com/lxc/incus/v7/shared/api"

	"github.com/unidoc/incus-sync/internal/config"
	"github.com/unidoc/incus-sync/internal/model"
)

type tOp struct{ incusclient.Operation }

func (tOp) WaitContext(context.Context) error { return nil }

// tSrv implements only GetInstance and UpdateInstance; anything else panics.
type tSrv struct {
	incusclient.InstanceServer
	profile map[string]string
	local   map[string]string
}

func (s *tSrv) instance() api.Instance {
	exp := map[string]string{}
	for k, v := range s.profile {
		exp[k] = v
	}
	loc := map[string]string{}
	for k, v := range s.local {
		exp[k] = v
		loc[k] = v
	}
	return api.Instance{Name: "web", InstancePut: api.InstancePut{Config: loc}, ExpandedConfig: exp}
}

func (s *tSrv) GetInstance(string) (*api.Instance, string, error) {
	i := s.instance()
	return &i, "etag", nil
}

func (s *tSrv) UpdateInstance(_ string, put api.InstancePut, _ string) (incusclient.Operation, error) {
	s.local = put.Config
	return tOp{}, nil
}

func tBackupSelects(exp map[string]string) string {
	switch strings.ToLower(exp[model.BackupExcludeKey]) {
	case "true", "1", "yes", "on":
		return "excluded"
	}
	if p := exp[model.BackupPolicyKey]; p != "" {
		return "selected:" + p
	}
	return "no-policy"
}

// plan -> apply -> what incus-backup selects -> plan again.
func tCycle(t *testing.T, desired model.Instance, srv *tSrv) string {
	var steps []string
	for round := 1; round <= 2; round++ {
		p := &Plan{}
		planInstanceBackup(p, "web", desired, srv.instance())
		if len(p.Entries) != 1 {
			t.Fatalf("round %d: %d entries", round, len(p.Entries))
		}
		e := p.Entries[0]
		steps = append(steps, fmt.Sprintf("plan%d=%s", round, e.Action))
		if round == 1 {
			if e.Action == ActionUpdate {
				if err := e.execUpdate(srv); err != nil {
					t.Fatal(err)
				}
			}
			steps = append(steps, "backup="+tBackupSelects(srv.instance().ExpandedConfig))
		}
	}
	return strings.Join(steps, "|")
}

func TestBackupBlockAgainstProfileKeys(t *testing.T) {
	policy := model.Instance{Name: "web", Backup: &model.InstanceBackup{Policy: "nightly"}}
	exclude := model.Instance{Name: "web", Backup: &model.InstanceBackup{Exclude: true}}
	for _, tc := range []struct {
		name    string
		desired model.Instance
		profile map[string]string
		local   map[string]string
		want    string
	}{
		{"control: no profile keys", policy, nil, nil,
			"plan1=update|backup=selected:nightly|plan2=match"},
		{"control: exclude wins over a local policy", exclude, nil, map[string]string{model.BackupPolicyKey: "nightly"},
			"plan1=update|backup=excluded|plan2=match"},
		{"profile sets exclude, fleet declares a policy", policy, map[string]string{model.BackupExcludeKey: "true"}, nil,
			"plan1=update|backup=selected:nightly|plan2=match"},
		{"same, policy already set locally", policy, map[string]string{model.BackupExcludeKey: "true"}, map[string]string{model.BackupPolicyKey: "nightly"},
			"plan1=update|backup=selected:nightly|plan2=match"},
	} {
		got := tCycle(t, tc.desired, &tSrv{profile: tc.profile, local: tc.local})
		t.Logf("%-48s %s", tc.name+":", got)
		if got != tc.want {
			t.Errorf("%s:\n got  %s\n want %s", tc.name, got, tc.want)
		}
	}
}

// A create entry is what a reviewer reads in `diff`; it should say it creates a VM, and which
// backup keys the new instance gets.
func TestCreateDetailsShowTypeAndBackup(t *testing.T) {
	desired := model.Instance{Name: "vm1", Type: model.InstanceTypeVM, OriginalImage: "images:debian/13",
		Backup: &model.InstanceBackup{Policy: "nightly"}}
	p := &Plan{}
	planInstances(p, &config.Fleet{Instances: map[string]model.Instance{"vm1": desired}}, nil)
	if len(p.Entries) != 1 || p.Entries[0].Action != ActionCreate {
		t.Fatalf("%+v", p.Entries)
	}
	d := strings.Join(p.Entries[0].Details, "; ")
	got := fmt.Sprintf("type-shown=%v|backup-shown=%v", strings.Contains(d, "virtual-machine"), strings.Contains(d, model.BackupPolicyKey))
	t.Logf("details: %s", d)
	if got != "type-shown=true|backup-shown=true" {
		t.Errorf("got %s", got)
	}
}
