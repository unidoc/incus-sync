package config

import "testing"

func TestHasAck(t *testing.T) {
	cases := []struct {
		desc string
		name string
		want bool
	}{
		{"", "world-open", false},
		{"just prose no tag", "world-open", false},
		{"Public HTTP (ack world-open)", "world-open", true},
		{"Public (ack   world-open   )", "world-open", true}, // extra whitespace
		{"Metrics (ack world-open, exposes-metrics)", "exposes-metrics", true},
		{"Metrics (ack world-open, exposes-metrics)", "world-open", true},
		{"Metrics (ack world-open, exposes-metrics)", "unknown-risk", false},
		{"Two tags (ack a) (ack b)", "b", true},
		{"Case (Ack world-open)", "world-open", false}, // literal `ack` prefix must match; only names are case-insensitive
		{"Case (ack WORLD-OPEN)", "world-open", true},
		// The old [ack: name] syntax must NOT work — it would force
		// operators to quote the description in YAML.
		{"Old syntax [ack: world-open]", "world-open", false},
	}
	for _, c := range cases {
		got := hasAck(c.desc, c.name)
		if got != c.want {
			t.Errorf("hasAck(%q, %q) = %v; want %v", c.desc, c.name, got, c.want)
		}
	}
}
