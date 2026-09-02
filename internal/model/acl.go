package model

import (
	"sort"

	"github.com/lxc/incus/v7/shared/api"
)

// ACL is our YAML representation of an Incus network ACL. Reuses Incus's own
// rule structs so schema and validation are identical to what `incus network
// acl edit` produces.
type ACL struct {
	Name        string               `yaml:"name"`
	Description string               `yaml:"description,omitempty"`
	Ingress     []api.NetworkACLRule `yaml:"ingress,omitempty"`
	Egress      []api.NetworkACLRule `yaml:"egress,omitempty"`
	Config      map[string]string    `yaml:"config,omitempty"`
}

// ACLFromAPI converts an Incus-returned ACL into our on-disk form.
func ACLFromAPI(a api.NetworkACL) ACL {
	return ACL{
		Name:        a.Name,
		Description: a.Description,
		Ingress:     a.Ingress,
		Egress:      a.Egress,
		Config:      map[string]string(a.Config),
	}
}

// ToPut returns the writable form for Incus updates.
func (a ACL) ToPut() api.NetworkACLPut {
	return api.NetworkACLPut{
		Description: a.Description,
		Ingress:     a.Ingress,
		Egress:      a.Egress,
		Config:      api.ConfigMap(a.Config),
	}
}

// ToPost returns the creation payload.
func (a ACL) ToPost() api.NetworkACLsPost {
	return api.NetworkACLsPost{
		NetworkACLPost: api.NetworkACLPost{Name: a.Name},
		NetworkACLPut:  a.ToPut(),
	}
}

// ACLsFile is the on-disk YAML for a list of ACLs.
type ACLsFile struct {
	ACLs []ACL `yaml:"acls"`
}

// Sort orders ACLs alphabetically by name for stable diffs.
func (f *ACLsFile) Sort() {
	sort.Slice(f.ACLs, func(i, j int) bool {
		return f.ACLs[i].Name < f.ACLs[j].Name
	})
}
