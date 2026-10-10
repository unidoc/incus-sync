package incus

import (
	"strings"
	"testing"

	"github.com/lxc/incus/v7/shared/api"

	"github.com/unidoc/incus-sync/internal/model"
)

func liveInst(name string, cfg map[string]string) api.Instance {
	return api.Instance{Name: name, InstancePut: api.InstancePut{Config: cfg}}
}

func backupEntries(p *Plan) []PlanEntry {
	var out []PlanEntry
	for _, e := range p.Entries {
		if e.Kind == "instance-config" {
			out = append(out, e)
		}
	}
	return out
}

func TestBackupBlockSetsPolicyKeyOnlyWhenDifferent(t *testing.T) {
	desired := model.Instance{Name: "web", Backup: &model.InstanceBackup{Policy: "nightly"}}
	p := &Plan{}
	planInstanceBackup(p, "web", desired, liveInst("web", map[string]string{}))
	es := backupEntries(p)
	if len(es) != 1 || es[0].Action != ActionUpdate || es[0].execUpdate == nil || !strings.Contains(es[0].Details[0], "user.backup.policy") {
		t.Fatalf("%+v", es)
	}
	p = &Plan{}
	planInstanceBackup(p, "web", desired, liveInst("web", map[string]string{model.BackupPolicyKey: "nightly"}))
	if es := backupEntries(p); len(es) != 1 || es[0].Action != ActionMatch {
		t.Fatalf("matching state must be a match: %+v", es)
	}
}

// Without a backup block sync must not strip a hand-set key.
func TestAbsentBackupBlockNeverTouchesHandSetKeys(t *testing.T) {
	p := &Plan{}
	planInstanceBackup(p, "web", model.Instance{Name: "web"}, liveInst("web", map[string]string{model.BackupPolicyKey: "hand-set"}))
	if len(p.Entries) != 0 {
		t.Fatalf("sync touched a key it does not own: %+v", p.Entries)
	}
}

func TestExcludeReplacesPolicyAndUnsetsIt(t *testing.T) {
	desired := model.Instance{Name: "web", Backup: &model.InstanceBackup{Exclude: true}}
	p := &Plan{}
	planInstanceBackup(p, "web", desired, liveInst("web", map[string]string{model.BackupPolicyKey: "nightly"}))
	es := backupEntries(p)
	if len(es) != 1 || len(es[0].Details) != 2 {
		t.Fatalf("expected set exclude + unset policy: %+v", es)
	}
	set, unset, managed := desired.BackupConfig()
	if !managed || set[model.BackupExcludeKey] != "true" || len(unset) != 1 || unset[0] != model.BackupPolicyKey {
		t.Fatalf("%v %v %v", set, unset, managed)
	}
}

func TestEmptyBackupBlockUnsetsBothKeys(t *testing.T) {
	desired := model.Instance{Name: "web", Backup: &model.InstanceBackup{}}
	_, unset, managed := desired.BackupConfig()
	if !managed || len(unset) != 2 {
		t.Fatalf("%v %v", unset, managed)
	}
}

func TestPolicyNameValidation(t *testing.T) {
	for _, ok := range []string{"nightly", "prod-2", "a.b_c"} {
		if !model.ValidBackupPolicyName(ok) {
			t.Errorf("%q rejected", ok)
		}
	}
	for _, bad := range []string{"", "has space", "a/b", strings.Repeat("x", 64), "ü"} {
		if model.ValidBackupPolicyName(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}
