package crashlog

// ipsRenderer renders a parsed Ips report (a JSON .ips of some bug_type) to
// display text.
type ipsRenderer func(*Ips) string

// ipsRenderers maps a report's bug_type (and its friendly name) to the renderer
// for that crash-log family. Each family registers its renderer from its own
// file's init(), so adding a new crash type is a new file plus a registration
// rather than another arm in a central switch.
var ipsRenderers = map[string]ipsRenderer{}

// registerIpsRenderer wires a renderer to one or more bug_type keys. Called from
// init() in each crash-log family's file.
func registerIpsRenderer(r ipsRenderer, bugTypes ...string) {
	for _, bt := range bugTypes {
		ipsRenderers[bt] = r
	}
}
