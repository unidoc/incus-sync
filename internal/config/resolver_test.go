package config

import (
	"strings"
	"testing"

	"github.com/unidoc/incus-sync/internal/model"
)

func fleetWithAliases(aliases map[string][]string) *Fleet {
	f := &Fleet{
		Aliases:     map[string]model.Alias{},
		AddressSets: map[string]model.AddressSet{},
		ACLs:        map[string]model.ACL{},
		Instances:   map[string]model.Instance{},
		Policies:    map[string]model.Policy{},
		origins:     map[string]string{},
	}
	for name, addrs := range aliases {
		f.Aliases[name] = model.Alias{Name: name, Addresses: addrs}
	}
	return f
}

func TestResolveAddressesFlat(t *testing.T) {
	f := fleetWithAliases(nil)
	got, err := f.ResolveAddresses([]string{"1.2.3.4", "5.6.7.8/32"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "1.2.3.4" || got[1] != "5.6.7.8/32" {
		t.Errorf("got %v", got)
	}
}

func TestResolveAddressesAliasExpansion(t *testing.T) {
	f := fleetWithAliases(map[string][]string{
		"lupin": {"203.0.113.10", "2001:db8:c012:f3ca::/64"},
	})
	got, err := f.ResolveAddresses([]string{"@lupin", "10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3, got %d: %v", len(got), got)
	}
	if got[2] != "10.0.0.1" {
		t.Errorf("expected literal last, got %v", got)
	}
}

func TestResolveAddressesNestedAlias(t *testing.T) {
	f := fleetWithAliases(map[string][]string{
		"lupin":     {"203.0.113.10"},
		"bogor":     {"198.51.100.20"},
		"web-hosts": {"@lupin", "@bogor"},
		"outer":     {"@web-hosts", "1.2.3.4"},
	})
	got, err := f.ResolveAddresses([]string{"@outer"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"203.0.113.10", "198.51.100.20", "1.2.3.4"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("got[%d]=%q want %q", i, got[i], want[i])
		}
	}
}

func TestResolveAddressesCycleDetected(t *testing.T) {
	f := fleetWithAliases(map[string][]string{
		"a": {"@b"},
		"b": {"@a"},
	})
	_, err := f.ResolveAddresses([]string{"@a"})
	if err == nil {
		t.Fatal("expected cycle error, got nil")
	}
	if !strings.Contains(err.Error(), "cycle") {
		t.Errorf("expected 'cycle' in %q", err)
	}
	if !strings.Contains(err.Error(), "a -> b -> a") {
		t.Errorf("expected full cycle path in %q", err)
	}
}

func TestResolveAddressesUnknownAlias(t *testing.T) {
	f := fleetWithAliases(nil)
	_, err := f.ResolveAddresses([]string{"@missing"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestResolveInstanceField(t *testing.T) {
	f := fleetWithAliases(nil)
	f.Instances["webapp"] = model.Instance{
		Name: "webapp",
		IP6:  "2001:db8:1::81",
	}
	got, err := f.ResolveAddresses([]string{"@webapp.ip6"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "2001:db8:1::81" {
		t.Errorf("got %v", got)
	}
}

func TestResolveInstanceFieldUnknownInstance(t *testing.T) {
	f := fleetWithAliases(nil)
	_, err := f.ResolveAddresses([]string{"@missing.ip6"})
	if err == nil {
		t.Fatal("expected error for unknown instance")
	}
	if !strings.Contains(err.Error(), "unknown instance") {
		t.Errorf("unexpected error %q", err)
	}
}

func TestResolveInstanceFieldMissingIP(t *testing.T) {
	f := fleetWithAliases(nil)
	f.Instances["webapp"] = model.Instance{Name: "webapp"} // no IP set
	_, err := f.ResolveAddresses([]string{"@webapp.ip6"})
	if err == nil {
		t.Fatal("expected error for missing IP")
	}
}

func TestResolveInstanceFieldUnknownField(t *testing.T) {
	f := fleetWithAliases(nil)
	f.Instances["webapp"] = model.Instance{Name: "webapp", IP6: "::1"}
	_, err := f.ResolveAddresses([]string{"@webapp.macaddr"})
	if err == nil {
		t.Fatal("expected error for unknown field")
	}
}

func TestEffectiveACLsPolicyOnlyOnEth0(t *testing.T) {
	f := fleetWithAliases(nil)
	f.ACLs["web-in"] = model.ACL{Name: "web-in"}
	f.Policies["web-tier"] = model.Policy{
		Name:     "web-tier",
		Selector: model.PolicySelector{Tags: []string{"web"}},
		Attach:   model.PolicyAttach{SecurityACLs: []string{"web-in"}},
	}
	inst := model.Instance{
		Name: "multi",
		Tags: []string{"web"},
		Devices: map[string]*model.InstanceDevice{
			"eth0": {SecurityACLs: []string{}}, // present but empty; kept to exercise the eth0 lookup
			"eth1": {},                         // wireguard-style NIC
		},
	}
	f.Instances["multi"] = inst

	eth0Names, _ := f.EffectiveACLs(inst, "eth0")
	if len(eth0Names) != 1 || eth0Names[0] != "web-in" {
		t.Errorf("eth0 should have web-in from policy; got %v", eth0Names)
	}
	eth1Names, _ := f.EffectiveACLs(inst, "eth1")
	if len(eth1Names) != 0 {
		t.Errorf("eth1 should have no policy-attached ACL; got %v", eth1Names)
	}
}

func TestResolveInternalKeywordPassesThrough(t *testing.T) {
	f := fleetWithAliases(nil)
	got, err := f.ResolveAddresses([]string{"@internal", "@external"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "@internal" || got[1] != "@external" {
		t.Errorf("expected keywords passed through, got %v", got)
	}
}

func TestResolveFieldMixesAliasAndAddressSet(t *testing.T) {
	f := fleetWithAliases(map[string][]string{
		"lupin": {"203.0.113.10"},
	})
	got, err := f.ResolveField("@lupin,$secure-servers,10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	// alias expands, $ passes through, literal passes through.
	if got != "203.0.113.10,$secure-servers,10.0.0.1" {
		t.Errorf("got %q", got)
	}
}
