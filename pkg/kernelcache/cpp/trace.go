package cpp

import (
	"fmt"
	"time"
)

type anchorMode uint8

const (
	anchorModeUnknown anchorMode = iota
	anchorModeSymbolExportSymtab
	anchorModePreferredFileStringFallback
	anchorModeGlobalStringFallback
)

func (m anchorMode) String() string {
	switch m {
	case anchorModeSymbolExportSymtab:
		return "symbol_export_symtab"
	case anchorModePreferredFileStringFallback:
		return "preferred_file_string_fallback"
	case anchorModeGlobalStringFallback:
		return "global_string_fallback"
	default:
		return "unknown"
	}
}

func (m anchorMode) usedFallback() bool {
	return m == anchorModePreferredFileStringFallback || m == anchorModeGlobalStringFallback
}

type scanPhaseTimings struct {
	buildTargets               time.Duration
	buildVMRangeIndex          time.Duration
	resolveAnchors             time.Duration
	buildPointerIndex          time.Duration
	collectCtorCandidates      time.Duration
	extractClassesFromCtor     time.Duration
	recoverStaticAnchorClasses time.Duration
	resolveVtables             time.Duration
}

type pointerReason uint8

const (
	pointerReasonOther pointerReason = iota
	pointerReasonMetaPtrDirectCall
	pointerReasonStaticDirectCall
	pointerReasonX2LoadRecovery
	pointerReasonGetMetaLiteral
	pointerReasonVtableStub
	pointerReasonCount
)

func (r pointerReason) String() string {
	switch r {
	case pointerReasonMetaPtrDirectCall:
		return "meta_ptr_direct_call"
	case pointerReasonStaticDirectCall:
		return "static_direct_call"
	case pointerReasonX2LoadRecovery:
		return "x2_load_recovery"
	case pointerReasonGetMetaLiteral:
		return "getmeta_literal"
	case pointerReasonVtableStub:
		return "vtable_stub"
	default:
		return "other"
	}
}

type pointerReasonStats struct {
	lookups        uint64
	forwardHits    uint64
	ownerIndexHits uint64
	slidAttempts   uint64
	rawAttempts    uint64
	successes      uint64
	misses         uint64
}

type pointerOwnerSource uint8

const (
	pointerOwnerSourceUnknown pointerOwnerSource = iota
	pointerOwnerSourceProvided
	pointerOwnerSourceIndexed
	pointerOwnerSourceOwnerFallback
	pointerOwnerSourceRootFallback
)

func (s *scanStats) setAnchorMode(mode anchorMode) {
	s.anchorMode = mode
}

func (s *scanStats) recordStaticDirectResolution(ctx wrapperContext, ok bool) {
	if !ok {
		return
	}
	if ctx.x0 != 0 {
		s.staticResolvedX0++
	}
	if ctx.x1 != 0 {
		s.staticResolvedX1++
	}
	if ctx.x2 != 0 {
		s.staticResolvedX2++
	}
	if ctx.x3 != 0 {
		s.staticResolvedX3++
	}
}

func (s *Scanner) ScanStatsLine() string {
	return fmt.Sprintf(
		"scan stats: classes=%d vtables=%d parent_meta=%d ptr_index=%d engines=%d ptr_hits=%d ptr_misses=%d",
		s.stats.discoveredClasses,
		s.stats.resolvedVtables,
		s.stats.resolvedParentMeta,
		s.stats.pointerIndexEntries,
		s.stats.engineCreations,
		s.stats.ptrCacheHits,
		s.stats.ptrCacheMisses,
	)
}

func (s *Scanner) TraceLogLines() []string {
	lines := []string{
		fmt.Sprintf(
			"trace: anchors mode=%s fallback=%t",
			s.stats.anchorMode,
			s.stats.anchorMode.usedFallback(),
		),
		fmt.Sprintf(
			"trace: phases build_targets=%s build_vm_range_index=%s resolve_anchors=%s build_pointer_index=%s",
			s.stats.phaseTimings.buildTargets,
			s.stats.phaseTimings.buildVMRangeIndex,
			s.stats.phaseTimings.resolveAnchors,
			s.stats.phaseTimings.buildPointerIndex,
		),
		fmt.Sprintf(
			"trace: phases collect_ctor_candidates=%s extract_classes_from_ctor=%s recover_static_anchor_classes=%s resolve_vtables=%s",
			s.stats.phaseTimings.collectCtorCandidates,
			s.stats.phaseTimings.extractClassesFromCtor,
			s.stats.phaseTimings.recoverStaticAnchorClasses,
			s.stats.phaseTimings.resolveVtables,
		),
		fmt.Sprintf(
			"trace: meta_ptr_infer calls=%d cache_hits=%d busy_short_circuits=%d max_depth=%d direct_call_hits=%d direct_call_misses=%d",
			s.stats.inferCalls,
			s.stats.inferCacheHits,
			s.stats.inferBusyHits,
			s.stats.inferMaxDepth,
			s.stats.metaPtrDirectHits,
			s.stats.metaPtrDirectMisses,
		),
		fmt.Sprintf(
			"trace: static_direct_call calls=%d cache_hits=%d resolved_x0=%d resolved_x1=%d resolved_x2=%d resolved_x3=%d",
			s.stats.staticDirectCalls,
			s.stats.staticDirectCache,
			s.stats.staticResolvedX0,
			s.stats.staticResolvedX1,
			s.stats.staticResolvedX2,
			s.stats.staticResolvedX3,
		),
	}

	dominantReason := pointerReasonOther
	dominantSlow := uint64(0)
	for reason := range pointerReasonCount {
		stats := s.stats.pointerReasons[reason]
		lines = append(lines, fmt.Sprintf(
			"trace: pointer_reason=%s lookups=%d forward_hits=%d owner_index_hits=%d slow_slid_attempts=%d slow_raw_attempts=%d successes=%d misses=%d",
			reason,
			stats.lookups,
			stats.forwardHits,
			stats.ownerIndexHits,
			stats.slidAttempts,
			stats.rawAttempts,
			stats.successes,
			stats.misses,
		))
		slow := stats.slidAttempts + stats.rawAttempts
		if slow > dominantSlow {
			dominantSlow = slow
			dominantReason = reason
		}
	}

	lines = append(lines, fmt.Sprintf(
		"trace: slow_summary anchor_fallback=%t dominant_pointer_reason=%s dominant_slow_attempts=%d",
		s.stats.anchorMode.usedFallback(),
		dominantReason,
		dominantSlow,
	))

	return lines
}
