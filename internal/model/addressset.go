package model

import (
	"fmt"
	"sort"

	"github.com/lxc/incus/v7/shared/api"
	"gopkg.in/yaml.v3"
)

// Address is one entry in an AddressSet with optional human comment.
// YAML accepts two forms:
//
//	addresses:
//	  - 203.0.113.10                                   # plain string
//	  - address: 198.51.100.20                        # structured with comment
//	    comment: bogor v4 — example hosting provider
//
// The comment lives only in git — Incus's API stores addresses as plain strings.
type Address struct {
	Value   string `yaml:"address"`
	Comment string `yaml:"comment,omitempty"`
}

// UnmarshalYAML accepts either a scalar string or a mapping with address/comment.
func (a *Address) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		a.Value = node.Value
		return nil
	case yaml.MappingNode:
		type raw struct {
			Address string `yaml:"address"`
			Comment string `yaml:"comment,omitempty"`
		}
		var r raw
		if err := node.Decode(&r); err != nil {
			return err
		}
		if r.Address == "" {
			return fmt.Errorf("address entry has empty 'address' field (line %d)", node.Line)
		}
		a.Value = r.Address
		a.Comment = r.Comment
		return nil
	default:
		return fmt.Errorf("address must be a string or {address, comment} mapping (line %d)", node.Line)
	}
}

// MarshalYAML emits a plain string when no comment; a mapping when comment is present.
// The type alias reuses Address's yaml tags — single source of truth — and
// avoids infinite recursion into MarshalYAML.
func (a Address) MarshalYAML() (any, error) {
	if a.Comment == "" {
		return a.Value, nil
	}
	type addressAlias Address
	return addressAlias(a), nil
}

// AddressSet is our extension over Incus's api.NetworkAddressSet: same fields
// plus per-address comments. Marshalled to YAML for git; converted to
// api.NetworkAddressSet{Put,Post} when talking to Incus.
type AddressSet struct {
	Name        string            `yaml:"name"`
	Description string            `yaml:"description,omitempty"`
	Addresses   []Address         `yaml:"addresses"`
	Config      map[string]string `yaml:"config,omitempty"`
}

// FromAPI converts an Incus-returned address set into our editable form.
// Comments start empty; the operator fills them in after `adopt`.
func AddressSetFromAPI(as api.NetworkAddressSet) AddressSet {
	out := AddressSet{
		Name:        as.Name,
		Description: as.Description,
		Config:      map[string]string(as.Config),
	}
	for _, s := range as.Addresses {
		out.Addresses = append(out.Addresses, Address{Value: s})
	}
	return out
}

// ToPut strips comments and returns the writable Incus form.
func (as AddressSet) ToPut() api.NetworkAddressSetPut {
	addrs := make([]string, 0, len(as.Addresses))
	for _, a := range as.Addresses {
		addrs = append(addrs, a.Value)
	}
	return api.NetworkAddressSetPut{
		Addresses:   addrs,
		Description: as.Description,
		Config:      api.ConfigMap(as.Config),
	}
}

// ToPost returns the creation payload.
func (as AddressSet) ToPost() api.NetworkAddressSetsPost {
	return api.NetworkAddressSetsPost{
		NetworkAddressSetPost: api.NetworkAddressSetPost{Name: as.Name},
		NetworkAddressSetPut:  as.ToPut(),
	}
}

// RawAddresses returns the raw address strings (values) in insertion order,
// dropping comments. Some entries may be alias/set references ("@foo", "$foo")
// which the resolver expands before sending to Incus.
func (as AddressSet) RawAddresses() []string {
	out := make([]string, len(as.Addresses))
	for i, a := range as.Addresses {
		out[i] = a.Value
	}
	return out
}

// AddressSetsFile is the on-disk YAML: a sorted list of address sets.
// A list (not a map) so ordering is stable in git diffs and human reorderable.
type AddressSetsFile struct {
	AddressSets []AddressSet `yaml:"address_sets"`
}

// Sort orders sets alphabetically by name for deterministic output.
func (f *AddressSetsFile) Sort() {
	sort.Slice(f.AddressSets, func(i, j int) bool {
		return f.AddressSets[i].Name < f.AddressSets[j].Name
	})
}
