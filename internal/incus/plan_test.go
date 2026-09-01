package incus

import (
	"strings"
	"testing"

	"github.com/lxc/incus/v7/shared/api"
)

func TestRuleListEqualIgnoresOrder(t *testing.T) {
	a := []api.NetworkACLRule{
		{Action: "allow", Protocol: "tcp", DestinationPort: "80", State: "enabled"},
		{Action: "allow", Protocol: "tcp", DestinationPort: "443", State: "enabled"},
	}
	b := []api.NetworkACLRule{
		{Action: "allow", Protocol: "tcp", DestinationPort: "443", State: "enabled"},
		{Action: "allow", Protocol: "tcp", DestinationPort: "80", State: "enabled"},
	}
	if !ruleListEqual(a, b) {
		t.Error("expected order-independent equal")
	}
}

func TestRuleListEqualDetectsDifference(t *testing.T) {
	a := []api.NetworkACLRule{
		{Action: "allow", Protocol: "tcp", DestinationPort: "80"},
	}
	b := []api.NetworkACLRule{
		{Action: "reject", Protocol: "tcp", DestinationPort: "80"},
	}
	if ruleListEqual(a, b) {
		t.Error("expected different action to be a diff")
	}
}

func TestRuleListEqualDifferentLengths(t *testing.T) {
	a := []api.NetworkACLRule{{Action: "allow"}}
	b := []api.NetworkACLRule{{Action: "allow"}, {Action: "reject"}}
	if ruleListEqual(a, b) {
		t.Error("expected length diff to fail")
	}
}

func TestDiffDeviceKeysOnlyManaged(t *testing.T) {
	live := map[string]string{
		"ipv6.address":  "old",
		"parent":        "br0", // unmanaged — must not show up
		"security.acls": "a,b",
		"nictype":       "bridged", // unmanaged
	}
	want := map[string]string{
		"ipv6.address":  "new",
		"security.acls": "a,b,c",
	}
	deltas := diffDeviceKeys(live, want)
	if len(deltas) != 2 {
		t.Fatalf("expected 2 diffs, got %d: %v", len(deltas), deltas)
	}
	// no delta about "parent" or "nictype"
	for _, d := range deltas {
		if d == "parent: ..." {
			t.Errorf("unmanaged key leaked into diff: %s", d)
		}
	}
}

func TestRuleSetDiffAddedRemoved(t *testing.T) {
	live := []api.NetworkACLRule{
		{Action: "allow", Protocol: "tcp", DestinationPort: "80"},
		{Action: "allow", Protocol: "tcp", DestinationPort: "443"},
	}
	want := []api.NetworkACLRule{
		{Action: "allow", Protocol: "tcp", DestinationPort: "443"},
		{Action: "allow", Protocol: "tcp", DestinationPort: "8443"},
	}
	added, removed := ruleSetDiff(live, want)
	if len(added) != 1 || added[0].DestinationPort != "8443" {
		t.Errorf("added = %v", added)
	}
	if len(removed) != 1 || removed[0].DestinationPort != "80" {
		t.Errorf("removed = %v", removed)
	}
}

func TestRuleOneLineFormatting(t *testing.T) {
	r := api.NetworkACLRule{
		Action:          "allow",
		Protocol:        "tcp",
		DestinationPort: "80,443",
		Source:          "$secure-servers",
		Description:     "management",
		State:           "enabled",
	}
	line := ruleOneLine(r)
	// Should include action, proto/port, source, description; skip "enabled" state
	for _, want := range []string{"allow", "tcp/80,443", "from $secure-servers", "(management)"} {
		if !strings.Contains(line, want) {
			t.Errorf("expected %q in %q", want, line)
		}
	}
	if strings.Contains(line, "[enabled]") {
		t.Errorf("default state should not show: %q", line)
	}
}

func TestAddressSetEqualCanonicalOrder(t *testing.T) {
	a := api.NetworkAddressSetPut{
		Description: "x",
		Addresses:   []string{"1.1.1.1", "2.2.2.2"},
	}
	b := api.NetworkAddressSetPut{
		Description: "x",
		Addresses:   []string{"2.2.2.2", "1.1.1.1"},
	}
	if !addressSetEqual(a, b) {
		t.Error("expected canonical-order equality")
	}
}
