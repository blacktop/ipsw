# Pipeline Implementation Status

**Last Updated:** 2025-10-26  
**Branch:** `feat/diff_pipeline`  
**Overall Progress:** ~85% (Event-driven streaming rollout in progress)  
**Status:** 🚧 Not yet production-ready (regression re-run pending)

---

## Executive Summary

The October 3 build delivered the first end-to-end pipeline, but we are now replacing the legacy “scan everything per handler” model with an event-driven ZIP/DMG walker. Each handler declares matchers (path regex, DMG type, etc.), the executor streams every file exactly once, and all subscribers receive the data they need while the DMG is mounted. This eliminates redundant `aea` decryptions and zip extractions, but several handlers still rely on the old cache/extractor paths. Until all handlers ride the new system (and the regression harness passes), we are keeping the project in **in-progress** state.

### What’s Done (Oct 26)
- ✅ `FileSubscription` / `FileEvent` infrastructure plus ZIP + DMG walkers.
- ✅ ZIP walker streams every archive entry (used by iBoot; firmware/kernelcache pending).
- ✅ DMG walker dispatches filesystem events and opportunistically populates the MachO cache.
- ✅ Files, Features, Launchd, DSC, and iBoot now subscribe to file events (no redundant work).
- ✅ Documentation + code updated to highlight the new architecture.

### What’s Still Open
1. **MachO / Entitlements / Launch Constraints** still depend on the legacy MachO cache pass. They need to subscribe directly to SystemOS events (or share a streaming parser) so we don’t double-parse and so their diff data accumulates during the walk.
2. **Firmware / Kernelcache** still call bespoke extractors that reopen the IPSW zip; they need ZIP matchers.
3. **Regression validation** (`hack/diff-regression.sh`) must be rerun after the remaining handlers migrate.

---

## Phase Snapshot

| Phase | Description | Status |
|-------|-------------|--------|
| Phase 1 | Core pipeline infrastructure | ✅ Complete (Oct 3) |
| Phase 2 | Handler migration (initial ports) | ✅ Complete (Oct 3) |
| Phase 3 | MachO cache system | ✅ Complete (legacy path) |
| Phase 4 | Profiling & optimization | ✅ Complete |
| Phase 5 | Event-driven streaming (matchers) | ⚠️ In progress |

### Phase 5 Breakdown

| Task | Status | Notes |
|------|--------|-------|
| 5.1 Introduce `FileSubscription` API + ZIP walker | ✅ |
| 5.2 Add DMG walker + opportunistic MachO caching | ✅ |
| 5.3 Convert Files/Features/Launchd | ✅ |
| 5.4 Convert DSC | ✅ |
| 5.5 Convert iBoot | ✅ |
| 5.6 Convert MachO/Entitlements/Launch Constraints | ⏳ |
| 5.7 Convert Kernelcache/Firmware | ⏳ |
| 5.8 Run regression suite + refresh FINAL_TEST_RESULTS | ⏳ |

---

## Handler Matrix (Oct 26)

| Handler | Source | Matcher? | Notes |
|---------|--------|----------|-------|
| Kernelcache | ZIP | ⏳ Pending | Still uses `kernelcache.Extract` |
| Firmware | ZIP | ⏳ Pending | Still uses legacy extractor |
| IBoot | ZIP | ✅ | Streams IM4P payloads |
| Files | ZIP + FileSystem/SystemOS/AppOS/Exclave | ✅ | Aggregates listings via events |
| Features | FileSystem DMG | ✅ | Collects plists from matcher |
| Launchd | FileSystem DMG | ✅ | Reads `/sbin/launchd` while mounted |
| DSC | SystemOS DMG | ✅ | Captures streamed DSC paths |
| MachO | SystemOS DMG | ⏳ | Still dependent on cache scan |
| Entitlements | SystemOS DMG | ⏳ | Cache-based (needs streaming) |
| Launch Constraints | SystemOS DMG | ⏳ | Cache-based (needs streaming) |
| KDK | External | ✅ | Unchanged |

---

## Next Actions

1. **Streaming MachO Consumers**  
   - Teach the MachO handler (and the cache itself) to ingest metadata during the SystemOS walk so Entitlements/Launch Constraints can subscribe instead of waiting for a second scan.

2. **ZIP Handlers**  
   - Add matchers for firmware/kernelcache so they read directly from the initial ZIP pass.

3. **Regression & Docs**  
   - Re-run `hack/diff-regression.sh` once all handlers are on the new flow and refresh `FINAL_TEST_RESULTS.md`.
   - Update `README`, `TASKS`, and `TESTING_GUIDE` as deliverables land (README + TASKS already updated in this commit).

---

## Historical Context (snapshot)

- Performance targets from the Oct 3 build (8m45s runtime, 721 MB peak) remain valid, but we need to re-verify after the matcher rollout since handler behavior is changing.
- Profiling infrastructure, cache metrics, and documentation from Phase 4 remain intact; they simply need another pass once the streaming work is complete.

---

**TL;DR** – We’re mid-flight on the streaming refresh. Core infrastructure + several handlers are done, but until MachO/Entitlements/Launch Constraints and the ZIP-only handlers use the new system (and the regression suite passes), keep the project in “in-progress” state. Updates will continue to land in this document as each matcher migration wraps up.*** End Patch
