package config

import (
	"path/filepath"
	"testing"
)

// TestExampleFleetValidates loads and semantically validates every host
// in examples/minimal-fleet. That directory is shipped as onboarding
// documentation (examples/minimal-fleet/README.md walks through it) —
// this test is what keeps it honest: a schema or naming-rule change
// that breaks the example fails here instead of silently rotting in
// the wild.
func TestExampleFleetValidates(t *testing.T) {
	dir, err := filepath.Abs(filepath.Join("..", "..", "examples", "minimal-fleet"))
	if err != nil {
		t.Fatal(err)
	}

	hosts, err := ListHosts(dir)
	if err != nil {
		t.Fatalf("ListHosts: %v", err)
	}
	if len(hosts) == 0 {
		t.Fatalf("%s declares no hosts", dir)
	}

	for _, host := range hosts {
		t.Run(host, func(t *testing.T) {
			f, err := Load(dir, host)
			if err != nil {
				t.Fatalf("Load(%q): %v", host, err)
			}
			if err := f.ValidateSemantic(); err != nil {
				t.Fatalf("ValidateSemantic(%q): %v", host, err)
			}
			// The example is meant to be a clean golden path — every
			// risk it deliberately demonstrates (e.g. world-open web
			// ingress) is acknowledged with an (ack ...) tag. A
			// warning here means either the example or the ack got
			// out of sync.
			for _, w := range f.Warnings {
				t.Errorf("unexpected warning for host %q: %s", host, w)
			}
		})
	}
}
