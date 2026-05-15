//go:build !linux

package mesh

import "context"

// defaultMDMPath is unused on non-Linux platforms (Enroll fails fast
// with ErrMeshUnsupportedOS before consulting it). Defining it here
// keeps the cliClient struct uniform across build configurations so
// tests don't need separate build tags to manipulate the field.
var defaultMDMPath = func() string { return "" }

// Enroll on non-Linux returns ErrMeshUnsupportedOS. The operator must
// perform the WARP enrollment by hand (`warp-cli registration new
// <team-slug>` is interactive — opens a browser callback) and then
// re-run `netbrain-beacon enroll` with `--skip-mesh`.
//
// The bundle v2 envelope on the platform side still carries the team
// slug, account ID, and service token, but on macOS / Windows that
// credential set is unusable headlessly in the current Cloudflare WARP
// CLI (the headless surface is OS-specific and only Linux is
// implemented in this beacon release — see ADR-009).
func (c *cliClient) Enroll(_ context.Context, _ Credentials) error {
	return ErrMeshUnsupportedOS
}
