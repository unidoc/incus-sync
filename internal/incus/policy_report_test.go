package incus

// A policy-violation plan entry is reported and gated like an update but never executed: `sync --apply --force`
// leaves the instance as it is, and a plan entry that has no executor is an error, not a silent skip.

import (
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/lxc/incus/v7/shared/api"

	"github.com/unidoc/incus-sync/internal/config"
)

func tLive(name string, cfg map[string]string) api.Instance {
	return api.Instance{Name: name, InstancePut: api.InstancePut{Config: cfg}}
}

// tApply runs Apply and returns "<first output line>|err=<err or panic>".
func tApply(p *Plan, dryRun bool) (outcome string) {
	r, w, _ := os.Pipe()
	stdout := os.Stdout
	os.Stdout = w
	var errStr string
	func() {
		defer func() {
			if rec := recover(); rec != nil {
				errStr = "PANIC"
			}
		}()
		if err := p.Apply(nil, dryRun); err != nil {
			errStr = err.Error()
		} else {
			errStr = "<nil>"
		}
	}()
	w.Close()
	os.Stdout = stdout
	out, _ := io.ReadAll(r)
	first := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
	return fmt.Sprintf("%s|err=%s", first, errStr)
}

// Each forbidden key (issue #5 acceptance list): the report must never panic, and dry-run and
// apply should both say what happens (the instance is left as is), not "~ update".
func TestPolicyReportIsNotAnUpdate(t *testing.T) {
	for _, kv := range [][2]string{{"security.privileged", "true"}, {"security.idmap.isolated", "false"}} {
		p := &Plan{}
		planInstances(p, &config.Fleet{}, []api.Instance{tLive("c1", map[string]string{kv[0]: kv[1]})})
		got := "dry=" + tApply(p, true) + " || apply=" + tApply(p, false)
		want := "dry=! policy violation instance c1 (left as is, reset it by hand)|err=<nil> || apply=! policy violation instance c1 (left as is, reset it by hand)|err=<nil>"
		t.Logf("%s: %s", kv[0], got)
		if got != want {
			t.Errorf("%s:\n got  %s\n want %s", kv[0], got, want)
		}
	}
}

// An ordinary update entry whose executor was forgotten (a future plan.go bug) must fail loudly,
// not be printed as a "policy violation" while apply reports success.
func TestForgottenExecutorIsAnError(t *testing.T) {
	p := &Plan{Entries: []PlanEntry{{
		Kind: "instance-device", Name: "web.eth0", Action: ActionUpdate,
		Details: []string{`security.acls: "a" → "a,b"`},
	}}}
	got := tApply(p, false)
	t.Logf("%s", got)
	if !strings.Contains(got, "err=update instance-device \"web.eth0\"") {
		t.Errorf("got %s, want an error naming the entry", got)
	}
}
