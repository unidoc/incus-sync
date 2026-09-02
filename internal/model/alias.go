package model

import "strings"

// Alias is a fleet-repo-only named group of addresses. Never pushed to
// Incus. Referenced elsewhere as "@name" and expanded to a list of literal
// addresses at render time.
//
// Aliases may reference other aliases; the resolver detects cycles.
//
// Address sets in Incus can only hold literal addresses (and other address
// sets referenced with $), so aliases are a purely tool-side abstraction
// giving human-meaningful names to groups of hosts. Grep-ability for
// hosts across the fleet is the primary motivation.
type Alias struct {
	Name        string   `yaml:"alias"`
	Description string   `yaml:"description,omitempty"`
	Addresses   []string `yaml:"addresses"`
}

// AliasRef returns the bare name from a "@name" token and ok=true; or
// ok=false when the token is not an alias reference.
func AliasRef(tok string) (string, bool) {
	tok = strings.TrimSpace(tok)
	if strings.HasPrefix(tok, "@") && len(tok) > 1 {
		return tok[1:], true
	}
	return "", false
}
