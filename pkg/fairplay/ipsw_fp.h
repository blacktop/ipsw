#ifndef IPSW_FP_H
#define IPSW_FP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IPSW_FP_ABI_VERSION UINT32_C(1)
#define IPSW_FP_PATH_MAX ((size_t)4096)
#define IPSW_FP_PARENT_SYNC_UNCONFIRMED UINT32_C(1)

#define IPSW_FP_OK INT32_C(0)
#define IPSW_FP_INVALID_ARGUMENT INT32_C(1)
#define IPSW_FP_LICENSE_ABSENT INT32_C(2)
#define IPSW_FP_UNSUPPORTED INT32_C(3)
#define IPSW_FP_PERMISSION INT32_C(4)
#define IPSW_FP_IO INT32_C(5)
#define IPSW_FP_PROCESSING INT32_C(6)
#define IPSW_FP_PANIC INT32_C(7)
#define IPSW_FP_BUFFER_TOO_SMALL INT32_C(8)

/* No function retains a pointer or transfers ownership of an allocation.
 * All nonempty spans must lie within one live allocation for the whole call.
 * Readable bytes must remain initialized and stable. Writable spans must be
 * exclusively accessible, and output cells must have their native alignment.
 * Rust cannot validate arbitrary nonnull pointers or concurrent access; these
 * are caller obligations. Detected null, alignment, extent and overlap errors
 * return IPSW_FP_INVALID_ARGUMENT without dereferencing invalid spans.
 *
 * These functions do not log errors or install a process-wide panic hook.
 * IPSW_FP_PANIC catches unwinding Rust panics only. The host's existing panic
 * hook still runs; aborts and invalid caller memory cannot be recovered here.
 * Opaque panic payloads are quarantined without running their destructors and
 * may retain an exceptional allocation until process exit. After IPSW_FP_PANIC,
 * the caller MUST retire the hosting process without retrying this backend.
 */
uint32_t ipsw_fp_abi_version(void);

/* Returns the maximum serialized authorization size without reading files. */
size_t ipsw_fp_auth_capacity(void);

/* Paths are nonempty Unix byte strings, without a terminating or embedded NUL,
 * and at most IPSW_FP_PATH_MAX bytes each. They may contain non-UTF-8 bytes.
 * flags must name a distinct writable uint32_t, disjoint from every input span.
 * After structural memory validation, flags is cleared before path content or
 * I/O validation. On success bit 0 indicates unconfirmed parent fsync durability;
 * all other bits are zero. The output directory must be new; it is not replaced.
 * No raw error text, account material or source paths cross this ABI.
 */
int32_t ipsw_fp_decrypt_v1(const uint8_t *ipa, size_t ipa_len,
                         const uint8_t *auth, size_t auth_len,
                         const uint8_t *out, size_t out_len, uint32_t *flags);

/* out and written must be disjoint writable storage. capacity must equal
 * ipsw_fp_auth_capacity(); smaller buffers return IPSW_FP_BUFFER_TOO_SMALL.
 * out may be NULL only when capacity is zero. Oversized buffers are rejected.
 * After structural memory validation, written is cleared; it remains zero on
 * failure and output bytes are unchanged. On success it reports the initialized
 * prefix of out; the remaining bytes are unchanged. No allocation is returned.
 *
 * Snapshots existing local authorization only: no output file, uid/gid change
 * or other credential mutation. macOS permission is required; other platforms
 * return IPSW_FP_UNSUPPORTED. Run only in an explicit short-lived helper for
 * privileged reads, never as a privilege-drop operation in a Go process.
 */
int32_t ipsw_fp_capture_auth_v1(uint8_t *out, size_t capacity, size_t *written);

#ifdef __cplusplus
}
#endif

#endif
