package config

import (
	"regexp"
	"strings"
)

// hasAck reports whether desc contains an ack list mentioning name.
// Example descriptions that suppress the "world-open" risk:
//
//	description: Public HTTP/HTTPS (ack world-open)
//	description: Web + metrics (ack world-open, exposes-metrics)
//
// Parentheses are used because `[...]` starts a YAML flow sequence and
// `: ` mid-scalar starts a mapping value in a plain scalar — either
// would force every ack'd description to be quoted. Parens are literal.
//
// The ack tag can appear anywhere in the description. Names are matched
// case-insensitively.
//
// Multi-risk aliases (e.g. "ack all") are intentionally NOT supported —
// each risk must be listed explicitly so a code review can see what the
// author actually acknowledged.
var ackRe = regexp.MustCompile(`\(ack\s+([^)]+)\)`)

func hasAck(desc, name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, m := range ackRe.FindAllStringSubmatch(desc, -1) {
		for _, tok := range strings.Split(m[1], ",") {
			if strings.ToLower(strings.TrimSpace(tok)) == name {
				return true
			}
		}
	}
	return false
}
