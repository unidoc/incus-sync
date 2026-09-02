package config

import (
	"strings"
	"testing"

	"github.com/unidoc/incus-sync/internal/model"
)

// TestValidateInstancesRequiresIP4PrefixAndGateway guards the bug found
// in code review: a static ip4 with no ip4_prefix_length/ip4_gateway
// used to render with no netmask and no gateway — silently broken
// networking. There is no safe default to guess (unlike ip6's /80
// convention), so validate must refuse outright.
func TestValidateInstancesRequiresIP4PrefixAndGateway(t *testing.T) {
	cases := []struct {
		name    string
		inst    model.Instance
		wantErr string
	}{
		{
			name:    "missing both",
			inst:    model.Instance{Name: "webapp", IP4: "203.0.113.10"},
			wantErr: "ip4_prefix_length is missing",
		},
		{
			name: "missing gateway only",
			inst: model.Instance{
				Name: "webapp", IP4: "203.0.113.10", IP4PrefixLength: 24,
			},
			wantErr: "ip4_gateway is missing",
		},
		{
			name: "invalid gateway",
			inst: model.Instance{
				Name: "webapp", IP4: "203.0.113.10", IP4PrefixLength: 24,
				IP4Gateway: "not-an-ip",
			},
			wantErr: "invalid ip4_gateway",
		},
		{
			name: "prefix out of range",
			inst: model.Instance{
				Name: "webapp", IP4: "203.0.113.10", IP4PrefixLength: 33,
				IP4Gateway: "203.0.113.1",
			},
			wantErr: "out of range",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := &Fleet{Instances: map[string]model.Instance{"webapp": c.inst}}
			err := f.validateInstances()
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("expected error containing %q, got %q", c.wantErr, err.Error())
			}
		})
	}
}

func TestValidateInstancesAcceptsCompleteIP4(t *testing.T) {
	f := &Fleet{Instances: map[string]model.Instance{
		"webapp": {
			Name: "webapp", IP4: "203.0.113.10", IP4PrefixLength: 24,
			IP4Gateway: "203.0.113.1",
		},
	}}
	if err := f.validateInstances(); err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}
