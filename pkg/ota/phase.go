package ota

import (
	"errors"
	"fmt"
	"os"
)

// Phase identifies the stage of OTA extraction that produced an error. The
// value set is a stable part of the ipsw machine-readable report contract:
// within a schema_version, values are never renamed or removed.
type Phase string

const (
	PhaseOTAOpen          Phase = "ota-open"
	PhaseAEADecrypt       Phase = "aea-decrypt"
	PhaseOTAInfo          Phase = "ota-info"
	PhaseOutputSetup      Phase = "output-setup"
	PhaseCryptexDiscovery Phase = "cryptex-discovery"
	PhaseCryptexPatch     Phase = "cryptex-patch"
	PhaseMount            Phase = "mount"
	PhaseDSCDiscovery     Phase = "dsc-discovery"
	PhasePayloadExtract   Phase = "payload-extract"
	PhaseCopy             Phase = "copy"
	PhaseCleanup          Phase = "cleanup"
)

// PhaseError attributes a failure to a Phase and to the OTA member being
// processed. Source is "" when the failure is not attributable to one member.
type PhaseError struct {
	Phase  Phase
	Source string
	Err    error
}

// Error names the failing OTA member and phase. When no member is
// attributable the phase adds nothing a caller can act on, so the underlying
// message is returned unchanged.
func (e *PhaseError) Error() string {
	if e.Source != "" {
		return fmt.Sprintf("%s: %s: %v", e.Source, e.Phase, e.Err)
	}
	return e.Err.Error()
}

// Unwrap keeps errors.Is/As working through the phase wrapper.
// internal/diff depends on errors.Is(err, ErrCryptexNotFound).
func (e *PhaseError) Unwrap() error { return e.Err }

// ErrNoDscInCryptexes reports that the OTA yielded no dyld_shared_cache from
// its cryptex members, either because it carries none (delta OTAs) or because
// none held a matching file. It means "this source does not apply", not "this
// source failed", and callers must not record it as an error.
var ErrNoDscInCryptexes = errors.New("no dyld_shared_cache found in OTA cryptexes")

// ExtractedFile pairs a materialized file with the OTA member it came from.
type ExtractedFile struct {
	Path   string // destination path on disk, exactly as written
	Source string // OTA member basename, e.g. "cryptex-system-arm64e"
}

// joinRemoveTempDir removes dir and joins any failure onto err. Extraction can
// move every file out and still leak its temp dir, so the removal result is
// part of the outcome rather than something to discard.
func joinRemoveTempDir(err error, source, dir string) error {
	rerr := os.RemoveAll(dir)
	if rerr == nil {
		return err
	}
	return errors.Join(err, wrapPhase(PhaseCleanup, source,
		fmt.Errorf("failed to remove temp dir %s: %w", dir, rerr)))
}

// wrapPhase attributes err to p/source. It leaves an already-attributed error
// untouched so an inner classification is never overwritten by an outer default.
//
// A joined error is attributed LEAF BY LEAF. Classifying the join as a whole
// would let one already-classified branch (typically a cleanup failure) shield
// its unclassified siblings, leaving the primary failure with no phase or
// source of its own.
func wrapPhase(p Phase, source string, err error) error {
	if err == nil {
		return nil
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		leaves := joined.Unwrap()
		wrapped := make([]error, 0, len(leaves))
		for _, leaf := range leaves {
			wrapped = append(wrapped, wrapPhase(p, source, leaf))
		}
		return errors.Join(wrapped...)
	}
	var pe *PhaseError
	if errors.As(err, &pe) {
		return err
	}
	return &PhaseError{Phase: p, Source: source, Err: err}
}
