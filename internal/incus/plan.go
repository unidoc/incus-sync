// Package incus, plan.go — compute what would change and apply the plan.
//
// The plan layer is shared by diff (compute + print) and sync (compute +
// apply). Objects are visited in dependency order: address sets first,
// then ACLs (which may reference address sets via $), then instances
// (which reference ACLs via device.security.acls).
//
// Safety rules baked in:
//   - Objects that live in Incus but are not in the fleet stay put.
//     Delete requires an explicit --prune flag in a future release.
//   - Instance device updates PATCH only managed keys. Unmanaged keys
//     survive.
//   - Updates re-fetch the object at apply time to pick up a fresh ETag
//     so we do not clobber concurrent changes.

package incus

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	incusclient "github.com/lxc/incus/v7/client"
	"github.com/lxc/incus/v7/shared/api"

	"github.com/unidoc/incus-sync/internal/config"
	"github.com/unidoc/incus-sync/internal/model"
)

// Action names the kind of change a plan entry represents.
type Action string

const (
	ActionCreate    Action = "create"
	ActionUpdate    Action = "update"
	ActionMatch     Action = "match"
	ActionUnmanaged Action = "unmanaged" // in Incus but not in fleet
)

// PlanEntry is a single decision the plan holds about one object.
type PlanEntry struct {
	Kind   string
	Name   string
	Action Action
	// Project is the Incus project scope this entry applies against.
	// For instances: the instance's declared project. For network
	// resources (ACLs, address-sets): the fleet's NetworkProject —
	// they live in one shared namespace since features.networks=false.
	Project string
	// Details are human-readable field diffs for Update, or a short label
	// for Create/Unmanaged.
	Details []string
	// Dangers are refuse-worthy changes: emptying an ACL, emptying an
	// address set, widening ingress-default from reject/drop to allow.
	// sync --apply refuses to execute entries with non-empty Dangers
	// unless --force is also passed.
	Dangers []string

	execCreate func(incusclient.InstanceServer) error
	execUpdate func(incusclient.InstanceServer) error
}

// HasDangers reports whether any entry in the plan is refuse-worthy.
func (p *Plan) HasDangers() bool {
	for _, e := range p.Entries {
		if len(e.Dangers) > 0 {
			return true
		}
	}
	return false
}

// Plan is an ordered list of entries. Order matches dependency order.
type Plan struct {
	Entries []PlanEntry
}

// Summary returns "N create, N update, N unchanged, N unmanaged".
func (p *Plan) Summary() string {
	var c, u, m, un int
	for _, e := range p.Entries {
		switch e.Action {
		case ActionCreate:
			c++
		case ActionUpdate:
			u++
		case ActionMatch:
			m++
		case ActionUnmanaged:
			un++
		}
	}
	return fmt.Sprintf("%d create, %d update, %d unchanged, %d unmanaged",
		c, u, m, un)
}

// ComputePlan queries live Incus state and diffs it against the fleet.
//
// Multi-project awareness:
//   - Network resources (ACLs, address-sets) are queried and managed via
//     fleet.NetworkProject scope (default: "default"). With
//     features.networks=false on all managed projects, they live in one
//     shared namespace anyway.
//   - Instances are queried per-project. Each instance in the fleet
//     declares its project; sync groups by project and iterates.
//
// The passed srv is expected to be UNSCOPED (or scoped to any project);
// this function calls srv.UseProject internally per resource type.
func ComputePlan(srv incusclient.InstanceServer, fleet *config.Fleet) (*Plan, error) {
	p := &Plan{}

	// Network resources — one query in NetworkProject scope.
	netSrv := srv.UseProject(fleet.NetworkProject)
	liveAS, err := netSrv.GetNetworkAddressSets()
	if err != nil {
		return nil, fmt.Errorf("list address sets in %q: %w", fleet.NetworkProject, err)
	}
	if err := planAddressSets(p, fleet, liveAS); err != nil {
		return nil, err
	}
	// Tag every network-resource entry with the network project scope.
	for i := range p.Entries {
		if p.Entries[i].Project == "" {
			p.Entries[i].Project = fleet.NetworkProject
		}
	}

	liveACLs, err := netSrv.GetNetworkACLs()
	if err != nil {
		return nil, fmt.Errorf("list ACLs in %q: %w", fleet.NetworkProject, err)
	}
	beforeACLs := len(p.Entries)
	if err := planACLs(p, fleet, liveACLs); err != nil {
		return nil, err
	}
	for i := beforeACLs; i < len(p.Entries); i++ {
		if p.Entries[i].Project == "" {
			p.Entries[i].Project = fleet.NetworkProject
		}
	}

	// Instances — per-project query. Group by declared project.
	instancesByProject := groupInstancesByProject(fleet)
	for _, project := range fleet.Projects {
		projSrv := srv.UseProject(project)
		liveInsts, err := projSrv.GetInstances(api.InstanceTypeAny)
		if err != nil {
			return nil, fmt.Errorf("list instances in %q: %w", project, err)
		}
		beforeInsts := len(p.Entries)
		fleetSlice := fleetInstancesForProject(fleet, instancesByProject[project])
		planInstances(p, fleetSlice, liveInsts)
		for i := beforeInsts; i < len(p.Entries); i++ {
			if p.Entries[i].Project == "" {
				p.Entries[i].Project = project
			}
		}
	}

	return p, nil
}

// groupInstancesByProject returns instance names grouped by their
// declared project. inst.Project is required at load time, so no
// fallback needed here.
func groupInstancesByProject(fleet *config.Fleet) map[string][]string {
	out := map[string][]string{}
	for name, inst := range fleet.Instances {
		out[inst.Project] = append(out[inst.Project], name)
	}
	return out
}

// fleetInstancesForProject returns a fleet-shaped view restricted to a
// specific subset of instances. Used so planInstances only diffs against
// the instances relevant to the current project scope.
func fleetInstancesForProject(fleet *config.Fleet, instanceNames []string) *config.Fleet {
	slice := *fleet // shallow copy
	slice.Instances = map[string]model.Instance{}
	for _, name := range instanceNames {
		slice.Instances[name] = fleet.Instances[name]
	}
	return &slice
}

// Apply executes create/update actions in order. dryRun prints intent
// without touching Incus.
//
// Each entry carries its own Project scope (set by ComputePlan). Apply
// switches srv.UseProject per entry so multi-project sync works from
// a single unscoped connection.
func (p *Plan) Apply(srv incusclient.InstanceServer, dryRun bool) error {
	for _, e := range p.Entries {
		scoped := srv
		if e.Project != "" {
			scoped = srv.UseProject(e.Project)
		}
		label := e.Name
		if e.Project != "" {
			label = fmt.Sprintf("%s (project %s)", e.Name, e.Project)
		}
		switch e.Action {
		case ActionCreate:
			if dryRun {
				fmt.Printf("  + create %s %s\n", e.Kind, label)
				for _, d := range e.Details {
					fmt.Printf("      %s\n", d)
				}
				continue
			}
			if err := e.execCreate(scoped); err != nil {
				return fmt.Errorf("create %s %q in project %q: %w", e.Kind, e.Name, e.Project, err)
			}
			fmt.Printf("  created %s %s\n", e.Kind, label)
		case ActionUpdate:
			if dryRun {
				fmt.Printf("  ~ update %s %s\n", e.Kind, label)
				for _, d := range e.Details {
					fmt.Printf("      %s\n", d)
				}
				continue
			}
			if err := e.execUpdate(scoped); err != nil {
				return fmt.Errorf("update %s %q in project %q: %w", e.Kind, e.Name, e.Project, err)
			}
			fmt.Printf("  updated %s %s\n", e.Kind, label)
		}
	}
	return nil
}

// ------- address sets -------

func planAddressSets(p *Plan, fleet *config.Fleet, live []api.NetworkAddressSet) error {
	liveByName := map[string]api.NetworkAddressSet{}
	for _, l := range live {
		l.Normalise()
		liveByName[l.Name] = l
	}

	for _, name := range sortedKeys(fleet.AddressSets) {
		desired := fleet.AddressSets[name]
		resolvedAddrs, err := fleet.ResolveAddresses(desired.RawAddresses())
		if err != nil {
			return fmt.Errorf("resolve address set %q: %w", name, err)
		}

		wantPut := api.NetworkAddressSetPut{
			Addresses:   resolvedAddrs,
			Description: desired.Description,
			Config:      api.ConfigMap(desired.Config),
		}

		if existing, ok := liveByName[name]; ok {
			if addressSetEqual(existing.Writable(), wantPut) {
				p.Entries = append(p.Entries, PlanEntry{
					Kind: "address-set", Name: name, Action: ActionMatch,
				})
			} else {
				var dangers []string
				if len(existing.Addresses) > 0 && len(wantPut.Addresses) == 0 {
					dangers = append(dangers,
						"would empty address_set — every rule referencing $"+name+" would match nothing (disables silently). sync --apply refuses without --force.")
				}
				p.Entries = append(p.Entries, PlanEntry{
					Kind: "address-set", Name: name, Action: ActionUpdate,
					Details:    fieldDiffAddressSet(existing.Writable(), wantPut),
					Dangers:    dangers,
					execUpdate: updateAddressSet(name, wantPut),
				})
			}
			delete(liveByName, name)
			continue
		}
		p.Entries = append(p.Entries, PlanEntry{
			Kind: "address-set", Name: name, Action: ActionCreate,
			Details: []string{fmt.Sprintf("%d addresses", len(resolvedAddrs))},
			execCreate: createAddressSet(api.NetworkAddressSetsPost{
				NetworkAddressSetPost: api.NetworkAddressSetPost{Name: name},
				NetworkAddressSetPut:  wantPut,
			}),
		})
	}

	for _, name := range sortedKeys(liveByName) {
		p.Entries = append(p.Entries, PlanEntry{
			Kind: "address-set", Name: name, Action: ActionUnmanaged,
			Details: []string{"exists in Incus, not in fleet — left alone"},
		})
	}
	return nil
}

func addressSetEqual(a, b api.NetworkAddressSetPut) bool {
	sortStrings(a.Addresses)
	sortStrings(b.Addresses)
	return a.Description == b.Description &&
		reflect.DeepEqual([]string(a.Addresses), []string(b.Addresses)) &&
		configMapEqual(a.Config, b.Config)
}

func fieldDiffAddressSet(live, want api.NetworkAddressSetPut) []string {
	var out []string
	if live.Description != want.Description {
		out = append(out, fmt.Sprintf("description: %q → %q", live.Description, want.Description))
	}
	sortStrings(live.Addresses)
	sortStrings(want.Addresses)
	if !reflect.DeepEqual([]string(live.Addresses), []string(want.Addresses)) {
		out = append(out, fmt.Sprintf("addresses: [%s] → [%s]",
			strings.Join(live.Addresses, ", "),
			strings.Join(want.Addresses, ", ")))
	}
	if !configMapEqual(live.Config, want.Config) {
		out = append(out, fmt.Sprintf("config: %v → %v", live.Config, want.Config))
	}
	return out
}

func createAddressSet(post api.NetworkAddressSetsPost) func(incusclient.InstanceServer) error {
	return func(srv incusclient.InstanceServer) error {
		return srv.CreateNetworkAddressSet(post)
	}
}

func updateAddressSet(name string, put api.NetworkAddressSetPut) func(incusclient.InstanceServer) error {
	return func(srv incusclient.InstanceServer) error {
		_, etag, err := srv.GetNetworkAddressSet(name)
		if err != nil {
			return err
		}
		return srv.UpdateNetworkAddressSet(name, put, etag)
	}
}

// ------- ACLs -------

func planACLs(p *Plan, fleet *config.Fleet, live []api.NetworkACL) error {
	liveByName := map[string]api.NetworkACL{}
	for _, l := range live {
		for i := range l.Ingress {
			l.Ingress[i].Normalise()
		}
		for i := range l.Egress {
			l.Egress[i].Normalise()
		}
		liveByName[l.Name] = l
	}

	for _, name := range sortedKeys(fleet.ACLs) {
		desired := fleet.ACLs[name]
		ingress, err := resolveRuleList(fleet, desired.Ingress)
		if err != nil {
			return fmt.Errorf("acl %q ingress: %w", name, err)
		}
		egress, err := resolveRuleList(fleet, desired.Egress)
		if err != nil {
			return fmt.Errorf("acl %q egress: %w", name, err)
		}

		wantPut := api.NetworkACLPut{
			Description: desired.Description,
			Ingress:     ingress,
			Egress:      egress,
			Config:      api.ConfigMap(desired.Config),
		}

		if existing, ok := liveByName[name]; ok {
			if aclEqual(existing.Writable(), wantPut) {
				p.Entries = append(p.Entries, PlanEntry{
					Kind: "acl", Name: name, Action: ActionMatch,
				})
			} else {
				var dangers []string
				oldTotal := len(existing.Ingress) + len(existing.Egress)
				newTotal := len(wantPut.Ingress) + len(wantPut.Egress)
				if oldTotal > 0 && newTotal == 0 {
					dangers = append(dangers,
						"would empty ACL — every device attached to this ACL would fall back to default action only. sync --apply refuses without --force.")
				}
				p.Entries = append(p.Entries, PlanEntry{
					Kind: "acl", Name: name, Action: ActionUpdate,
					Details:    fieldDiffACL(existing.Writable(), wantPut),
					Dangers:    dangers,
					execUpdate: updateACL(name, wantPut),
				})
			}
			delete(liveByName, name)
			continue
		}
		p.Entries = append(p.Entries, PlanEntry{
			Kind: "acl", Name: name, Action: ActionCreate,
			Details: []string{fmt.Sprintf("%d ingress, %d egress", len(ingress), len(egress))},
			execCreate: createACL(api.NetworkACLsPost{
				NetworkACLPost: api.NetworkACLPost{Name: name},
				NetworkACLPut:  wantPut,
			}),
		})
	}

	for _, name := range sortedKeys(liveByName) {
		p.Entries = append(p.Entries, PlanEntry{
			Kind: "acl", Name: name, Action: ActionUnmanaged,
			Details: []string{"exists in Incus, not in fleet — left alone"},
		})
	}
	return nil
}

func resolveRuleList(fleet *config.Fleet, rules []api.NetworkACLRule) ([]api.NetworkACLRule, error) {
	out := make([]api.NetworkACLRule, len(rules))
	for i, r := range rules {
		var err error
		r.Source, err = fleet.ResolveField(r.Source)
		if err != nil {
			return nil, err
		}
		r.Destination, err = fleet.ResolveField(r.Destination)
		if err != nil {
			return nil, err
		}
		r.Normalise()
		out[i] = r
	}
	return out, nil
}

func aclEqual(a, b api.NetworkACLPut) bool {
	return a.Description == b.Description &&
		ruleListEqual(a.Ingress, b.Ingress) &&
		ruleListEqual(a.Egress, b.Egress) &&
		configMapEqual(a.Config, b.Config)
}

func ruleListEqual(a, b []api.NetworkACLRule) bool {
	if len(a) != len(b) {
		return false
	}
	// ACL rules are order-independent per Incus docs. Sort a canonical
	// projection so lexical reorder is not a diff.
	ka := ruleKeys(a)
	kb := ruleKeys(b)
	sort.Strings(ka)
	sort.Strings(kb)
	return reflect.DeepEqual(ka, kb)
}

func ruleKeys(rs []api.NetworkACLRule) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = ruleKey(r)
	}
	return out
}

func fieldDiffACL(live, want api.NetworkACLPut) []string {
	var out []string
	if live.Description != want.Description {
		out = append(out, fmt.Sprintf("description: %q → %q", live.Description, want.Description))
	}
	if added, removed := ruleSetDiff(live.Ingress, want.Ingress); len(added)+len(removed) > 0 {
		out = append(out, "ingress rules:")
		for _, r := range removed {
			out = append(out, "  - "+ruleOneLine(r))
		}
		for _, r := range added {
			out = append(out, "  + "+ruleOneLine(r))
		}
	}
	if added, removed := ruleSetDiff(live.Egress, want.Egress); len(added)+len(removed) > 0 {
		out = append(out, "egress rules:")
		for _, r := range removed {
			out = append(out, "  - "+ruleOneLine(r))
		}
		for _, r := range added {
			out = append(out, "  + "+ruleOneLine(r))
		}
	}
	if !configMapEqual(live.Config, want.Config) {
		out = append(out, "config changed")
	}
	return out
}

// ruleSetDiff computes symmetric-set difference between two rule slices.
// ACL rules are order-independent per Incus, so we compare by canonical
// key rather than positionally. Returns (added, removed).
func ruleSetDiff(live, want []api.NetworkACLRule) (added, removed []api.NetworkACLRule) {
	liveKeys := map[string]api.NetworkACLRule{}
	for _, r := range live {
		liveKeys[ruleKey(r)] = r
	}
	wantKeys := map[string]api.NetworkACLRule{}
	for _, r := range want {
		wantKeys[ruleKey(r)] = r
	}
	for k, r := range wantKeys {
		if _, ok := liveKeys[k]; !ok {
			added = append(added, r)
		}
	}
	for k, r := range liveKeys {
		if _, ok := wantKeys[k]; !ok {
			removed = append(removed, r)
		}
	}
	return added, removed
}

func ruleKey(r api.NetworkACLRule) string {
	return fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s|%s|%s",
		r.Action, r.Source, r.Destination, r.Protocol,
		r.SourcePort, r.DestinationPort,
		r.ICMPType, r.ICMPCode, r.State, r.Description)
}

// ruleOneLine renders a rule as a compact human string for diff output.
// Only informational — never parsed back.
func ruleOneLine(r api.NetworkACLRule) string {
	var b strings.Builder
	b.WriteString(r.Action)
	if r.Protocol != "" {
		b.WriteString(" ")
		b.WriteString(r.Protocol)
	}
	if r.DestinationPort != "" {
		b.WriteString("/")
		b.WriteString(r.DestinationPort)
	}
	if r.Source != "" {
		b.WriteString(" from ")
		b.WriteString(r.Source)
	}
	if r.Destination != "" {
		b.WriteString(" to ")
		b.WriteString(r.Destination)
	}
	if r.Description != "" {
		b.WriteString("  (")
		b.WriteString(r.Description)
		b.WriteString(")")
	}
	if r.State != "" && r.State != "enabled" {
		b.WriteString(" [")
		b.WriteString(r.State)
		b.WriteString("]")
	}
	return b.String()
}

func createACL(post api.NetworkACLsPost) func(incusclient.InstanceServer) error {
	return func(srv incusclient.InstanceServer) error {
		return srv.CreateNetworkACL(post)
	}
}

func updateACL(name string, put api.NetworkACLPut) func(incusclient.InstanceServer) error {
	return func(srv incusclient.InstanceServer) error {
		_, etag, err := srv.GetNetworkACL(name)
		if err != nil {
			return err
		}
		return srv.UpdateNetworkACL(name, put, etag)
	}
}

// ------- instances -------

// forbiddenInstanceConfig enforces fleet-wide container isolation. Any
// live instance whose config has these keys set to unsafe values gets
// surfaced as a plan-time refusal, so an operator (or attacker with
// fleet write) can't quietly turn off idmap or privileged=false via
// `incus config set` and have sync accept the state.
var forbiddenInstanceConfig = map[string]string{
	"security.privileged":     "true",
	"security.idmap.isolated": "false",
	"security.nesting":        "true",
}

func planInstances(p *Plan, fleet *config.Fleet, live []api.Instance) {
	liveByName := map[string]api.Instance{}
	for _, l := range live {
		liveByName[l.Name] = l
	}
	fleetHas := map[string]bool{}
	for n := range fleet.Instances {
		fleetHas[n] = true
	}

	// Surface any live instance that violates fleet isolation policy.
	// Reported as danger — sync --apply refuses without --force.
	for _, l := range live {
		for k, forbidden := range forbiddenInstanceConfig {
			if got, ok := l.Config[k]; ok && got == forbidden {
				p.Entries = append(p.Entries, PlanEntry{
					Kind: "instance", Name: l.Name, Action: ActionUpdate,
					Details: []string{fmt.Sprintf("policy violation: %s=%q", k, got)},
					Dangers: []string{fmt.Sprintf(
						"instance %q has %s=%q which violates fleet isolation policy. "+
							"Reset via `incus config unset %s %s`. sync --apply refuses without --force.",
						l.Name, k, got, l.Name, k)},
				})
			}
		}
	}

	for _, name := range sortedKeys(fleet.Instances) {
		desired := fleet.Instances[name]
		existing, ok := liveByName[name]
		if !ok {
			if desired.OriginalImage == "" {
				p.Entries = append(p.Entries, PlanEntry{
					Kind: "instance", Name: name, Action: ActionUnmanaged,
					Details: []string{"instance file present but container missing in Incus and no image: field set (sync cannot create)"},
				})
				continue
			}
			// Compute effective ACLs for each declared device up front so
			// the container is created with the right networking on first boot.
			devs := map[string]map[string]string{}
			for devName, dev := range desired.EffectiveDevices() {
				if dev == nil {
					continue
				}
				m := dev.ToDeviceMap()
				if effective, _ := fleet.EffectiveACLs(desired, devName); len(effective) > 0 {
					m["security.acls"] = strings.Join(effective, ",")
				}
				devs[devName] = m
			}
			// Resolve template names → on-disk paths at plan time so the
			// execCreate closure has no runtime fleet dependency.
			var templatePaths []string
			if desired.Provision != nil {
				for _, tName := range desired.Provision.Templates {
					if t, ok := fleet.Templates[tName]; ok {
						templatePaths = append(templatePaths, t.Path)
					}
				}
			}
			details := []string{
				fmt.Sprintf("original_image: %s", desired.OriginalImage),
				fmt.Sprintf("profiles: %v", instanceProfiles(desired)),
				fmt.Sprintf("devices: %v", sortedKeys(devs)),
			}
			if desired.Provision != nil && len(desired.Provision.Templates) > 0 {
				details = append(details, fmt.Sprintf("templates: %v", desired.Provision.Templates))
			}
			p.Entries = append(p.Entries, PlanEntry{
				Kind: "instance", Name: name, Action: ActionCreate,
				Details:    details,
				execCreate: createInstance(desired, devs, templatePaths, fleet.Secrets),
			})
			continue
		}

		effectiveDevs := desired.EffectiveDevices()
		if effectiveDevs == nil && len(desired.Devices) == 0 {
			// Flat form with nothing declared (no acls, no
			// ingress/egress-default). EffectiveDevices() returns nil
			// here for the CREATE path's benefit — "don't set any
			// device override on a brand-new container" — but for an
			// EXISTING instance that nil must not mean "leave eth0
			// alone forever": if the operator just emptied a
			// previously-populated acls: block, eth0 still needs to be
			// diffed against an empty want so the removal is detected
			// and the "loses all ACLs" danger gate below can fire,
			// instead of the whole instance silently vanishing from
			// the plan.
			effectiveDevs = map[string]*model.InstanceDevice{"eth0": {}}
		}
		for _, devName := range sortedKeys(effectiveDevs) {
			dev := effectiveDevs[devName]
			if dev == nil {
				continue
			}
			wantMap := dev.ToDeviceMap()
			// Replace security.acls with effective merge (device + policies).
			effective, _ := fleet.EffectiveACLs(desired, devName)
			if len(effective) > 0 {
				wantMap["security.acls"] = strings.Join(effective, ",")
			}

			liveDev := deviceFromInstance(existing, devName)
			if liveDev == nil {
				liveDev = map[string]string{}
			}

			deltas := diffDeviceKeys(liveDev, wantMap)
			if len(deltas) == 0 {
				p.Entries = append(p.Entries, PlanEntry{
					Kind: "instance-device", Name: name + "." + devName, Action: ActionMatch,
				})
				continue
			}
			var dangers []string
			liveIng := liveDev["security.acls.default.ingress.action"]
			wantIng := wantMap["security.acls.default.ingress.action"]
			if (liveIng == "reject" || liveIng == "drop" || liveIng == "") && wantIng == "allow" {
				dangers = append(dangers,
					"widens ingress-default from "+quoteOr(liveIng, "unset")+" to \"allow\" — container becomes world-open. sync --apply refuses without --force.")
			}
			liveACLs := liveDev["security.acls"]
			wantACLs := wantMap["security.acls"]
			if liveACLs != "" && wantACLs == "" {
				dangers = append(dangers,
					"removes all attached ACLs — device falls back to ingress-default only. sync --apply refuses without --force.")
			}
			unset := unsetDeviceKeys(liveDev, wantMap)
			p.Entries = append(p.Entries, PlanEntry{
				Kind: "instance-device", Name: name + "." + devName,
				Action:     ActionUpdate,
				Details:    deltas,
				Dangers:    dangers,
				execUpdate: updateInstanceDevice(name, devName, wantMap, unset),
			})
		}
	}
	// Live containers with no matching fleet file: never auto-deleted.
	// Print as unmanaged so a reviewer knows they exist.
	for _, name := range sortedKeys(liveByName) {
		if fleetHas[name] {
			continue
		}
		p.Entries = append(p.Entries, PlanEntry{
			Kind: "instance", Name: name, Action: ActionUnmanaged,
			Details: []string{"container exists in Incus but no fleet file — no auto-delete (run `incus delete " + name + "` manually)"},
		})
	}
}

// createInstance builds an api.InstancesPost and creates the container.
// eth0's security.acls are already the effective (merged) list, so the
// container is correctly firewalled from first boot.
func createInstance(desired model.Instance, devices map[string]map[string]string, templatePaths []string, secrets map[string]any) func(incusclient.InstanceServer) error {
	return func(srv incusclient.InstanceServer) error {
		source, err := parseImageSource(desired.OriginalImage)
		if err != nil {
			return err
		}
		start := true
		if desired.Start != nil {
			start = *desired.Start
		}
		profiles := instanceProfiles(desired)

		// Device overrides at create time need a full device spec — Incus
		// rejects a partial device with "Invalid device type ''". At
		// UPDATE time Incus merges with the existing local device, so
		// security.acls-only overrides are fine there.
		//
		// Fix: read the base device (type, network, nictype, ...) from
		// the profile stack and merge our security.acls* keys on top.
		// First profile that declares the device wins the base — matches
		// Incus's own profile-resolution order.
		devices = fillDevicesFromProfiles(srv, profiles, devices)

		req := api.InstancesPost{
			InstancePut: api.InstancePut{
				Description: desired.Description,
				Devices:     devices,
				Profiles:    profiles,
			},
			Name:   desired.Name,
			Source: source,
			Type:   api.InstanceTypeContainer,
			Start:  start,
		}
		printStep("      launching container (image %s)…", desired.OriginalImage)
		t0 := time.Now()
		op, err := srv.CreateInstance(req)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()
		if err := op.WaitContext(ctx); err != nil {
			return fmt.Errorf("instance %q create did not complete in 120s: %w", desired.Name, err)
		}
		printDone("      launched", time.Since(t0))
		// Post-create health: if Start was true, verify the container
		// actually reached RUNNING. A silent STOPPED result hides
		// image-pull or first-boot failures.
		if start {
			state, _, err := srv.GetInstanceState(desired.Name)
			if err != nil {
				return fmt.Errorf("instance %q created but state lookup failed: %w", desired.Name, err)
			}
			if state.Status != "Running" {
				return fmt.Errorf(
					"instance %q created but is in state %q (expected Running) — check `incus info %s` and `incus console --show-log %s`",
					desired.Name, state.Status, desired.Name, desired.Name)
			}
			printStep("      status: %s", state.Status)
		}

		// One-shot provisioning: interface template + raw files + after
		// commands. Runs only on create; never again. Empty spec is a no-op.
		//
		// If provision fails, delete the half-provisioned container so a
		// re-sync recreates cleanly. Leaving a broken container around
		// means subsequent sync passes see it as "existing" and skip both
		// create AND provision.
		if err := provisionContainer(srv, desired, templatePaths, secrets); err != nil {
			cleanupInstance(srv, desired.Name)
			return fmt.Errorf(
				"instance %q created but provisioning failed: %w\n"+
					"        the container was deleted so the next sync can retry cleanly",
				desired.Name, err)
		}
		return nil
	}
}

// fillDevicesFromProfiles copies base device keys (type, network, nictype,
// mtu, ...) from the profile stack into the create-time devices map so the
// override is a complete device spec. Called only when Devices already has
// entries — a device we do NOT override stays fully provided by profiles.
//
// Profile order matches Incus's own resolution: earlier profiles are
// defaults, later profiles win on conflicts. We walk in that order and let
// each profile set base keys we haven't yet, so the final base reflects
// the effective post-merge profile view.
//
// Overlay order: profile base first, our overrides last (win).
func fillDevicesFromProfiles(srv incusclient.InstanceServer, profiles []string, devices map[string]map[string]string) map[string]map[string]string {
	if len(devices) == 0 {
		return devices
	}
	base := map[string]map[string]string{}
	for _, pname := range profiles {
		prof, _, err := srv.GetProfile(pname)
		if err != nil {
			continue
		}
		for devName, dev := range prof.Devices {
			if _, wanted := devices[devName]; !wanted {
				continue
			}
			if base[devName] == nil {
				base[devName] = map[string]string{}
			}
			for k, v := range dev {
				base[devName][k] = v
			}
		}
	}
	out := map[string]map[string]string{}
	for devName, ourDev := range devices {
		merged := map[string]string{}
		for k, v := range base[devName] {
			merged[k] = v
		}
		for k, v := range ourDev {
			merged[k] = v
		}
		out[devName] = merged
	}
	return out
}

// cleanupInstance stops and deletes a container. Called on provisioning
// failure so the next sync sees a clean slate. Best-effort — logs on failure
// but does not fail the caller further.
func cleanupInstance(srv incusclient.InstanceServer, name string) {
	stopReq := api.InstanceStatePut{Action: "stop", Force: true, Timeout: 30}
	if op, err := srv.UpdateInstanceState(name, stopReq, ""); err == nil {
		_ = op.Wait()
	}
	if op, err := srv.DeleteInstance(name); err == nil {
		_ = op.Wait()
	}
}

// instanceProfiles returns the profile list sync applies at creation.
// Defaults to ["default"] — each project's own `default` profile
// carries that project's device configuration (bridge, ACLs, disk
// pool). No project-name profile duplication needed.
//
// Instance yaml can override with an explicit `profiles:` list if a
// container needs a non-default profile stack.
func instanceProfiles(i model.Instance) []string {
	if len(i.Profiles) > 0 {
		return i.Profiles
	}
	return []string{"default"}
}

// parseImageSource turns "images:alpine/3.24" or "images:debian/12" into
// an Incus source pointing at the public simplestreams server. For local
// or custom remotes, extend this parser.
func parseImageSource(image string) (api.InstanceSource, error) {
	if strings.HasPrefix(image, "images:") {
		alias := strings.TrimPrefix(image, "images:")
		return api.InstanceSource{
			Type:     "image",
			Server:   "https://images.linuxcontainers.org",
			Protocol: "simplestreams",
			Alias:    alias,
		}, nil
	}
	return api.InstanceSource{}, fmt.Errorf("only images:<alias> form supported; got %q", image)
}

// deviceFromInstance returns the *local* Devices map for devName, falling
// back to ExpandedDevices only for comparison purposes. When we PATCH,
// we write to local Devices — see updateInstanceDevice.
func deviceFromInstance(inst api.Instance, devName string) map[string]string {
	if inst.Devices != nil {
		if d, ok := inst.Devices[devName]; ok {
			return d
		}
	}
	if inst.ExpandedDevices != nil {
		return inst.ExpandedDevices[devName]
	}
	return nil
}

// managedKeyUniverse returns every key diffDeviceKeys and
// unsetDeviceKeys need to consider: everything in want, plus every key
// this tool ever manages (model.ManagedDeviceKeys()). Without the
// latter, a managed key that's present in live but absent from want
// (an operator removed it from the fleet file) is invisible to the
// diff — sortedKeys(want) alone only ever sees keys the fleet still
// wants, never ones it stopped wanting.
func managedKeyUniverse(want map[string]string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(k string) {
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	for _, k := range model.ManagedDeviceKeys() {
		add(k)
	}
	for k := range want {
		add(k)
	}
	sort.Strings(out)
	return out
}

// diffDeviceKeys returns human-readable diffs for every managed key:
// value changes, new keys, AND managed keys present in live but
// removed from want (reported as "→ (unset)"). Extra unmanaged keys in
// live are still ignored — those are not ours regardless.
func diffDeviceKeys(live, want map[string]string) []string {
	var out []string
	for _, k := range managedKeyUniverse(want) {
		wv, wantHas := want[k]
		lv, liveHas := live[k]
		switch {
		case wantHas && !liveHas:
			out = append(out, fmt.Sprintf("%s: (unset) → %q", k, wv))
		case wantHas && liveHas && lv != wv:
			out = append(out, fmt.Sprintf("%s: %q → %q", k, lv, wv))
		case !wantHas && liveHas && lv != "":
			out = append(out, fmt.Sprintf("%s: %q → (unset)", k, lv))
		}
	}
	return out
}

// unsetDeviceKeys returns managed keys present in live but no longer
// wanted. updateInstanceDevice must delete() these from the device map
// it PATCHes — merely omitting them from patch is not enough, since a
// stale value already present in inst.Devices[devName] survives
// untouched otherwise.
func unsetDeviceKeys(live, want map[string]string) []string {
	var out []string
	for _, k := range managedKeyUniverse(want) {
		if _, wantHas := want[k]; wantHas {
			continue
		}
		if lv, liveHas := live[k]; liveHas && lv != "" {
			out = append(out, k)
		}
	}
	return out
}

func updateInstanceDevice(name, devName string, patch map[string]string, unset []string) func(incusclient.InstanceServer) error {
	return func(srv incusclient.InstanceServer) error {
		inst, etag, err := srv.GetInstance(name)
		if err != nil {
			return err
		}
		if inst.Devices == nil {
			inst.Devices = map[string]map[string]string{}
		}
		// Local Devices map holds ONLY managed keys plus the immutable
		// device identity keys (type, network/parent). Without `type`,
		// Incus refuses the update ("Missing device type in config").
		// We seed those from ExpandedDevices so a container whose eth0
		// is entirely profile-provided still gets a valid local override
		// on the first patch. Mutable profile keys (MTU, etc.) are NOT
		// seeded — they stay profile-provided.
		dev := inst.Devices[devName]
		if dev == nil {
			dev = map[string]string{}
		}
		if _, hasType := dev["type"]; !hasType {
			if expanded, ok := inst.ExpandedDevices[devName]; ok {
				if t, ok := expanded["type"]; ok {
					dev["type"] = t
				}
				// nic requires network or parent to identify the bridge.
				if v, ok := expanded["network"]; ok {
					dev["network"] = v
				} else if v, ok := expanded["parent"]; ok {
					dev["parent"] = v
				}
			}
		}
		for _, k := range unset {
			delete(dev, k)
		}
		for k, v := range patch {
			dev[k] = v
		}
		inst.Devices[devName] = dev

		op, err := srv.UpdateInstance(name, inst.Writable(), etag)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if err := op.WaitContext(ctx); err != nil {
			return fmt.Errorf("instance %q update did not complete in 60s (check `incus operation list`): %w", name, err)
		}
		return nil
	}
}

// ------- helpers -------

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortStrings(s []string) {
	sort.Strings(s)
}

// quoteOr renders s as "s" or returns the fallback literal when s is empty.
// Used in danger messages to distinguish an explicit reject/drop from an unset key.
func quoteOr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return "\"" + s + "\""
}

func configMapEqual(a, b api.ConfigMap) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return reflect.DeepEqual(a, b)
}

// Ensure model import stays live for future extensions (e.g. explicit
// device-key allowlist enforcement in sync).
var _ = model.AliasRef
