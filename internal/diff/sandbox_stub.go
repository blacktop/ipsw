//go:build !sandbox

package diff

func (d *Diff) parseSandboxProfiles() (string, error) {
	return "", ErrSandboxDiffUnavailable
}
