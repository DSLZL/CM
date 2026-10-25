#ifndef CM_MOD_V21_H
#define CM_MOD_V21_H
#include "cm_mod_v2.h"

#define CM_V21_CAPABILITY "core.exec_output_limit.v1"
#define CM_V21_KEEP UINT64_C(0)
#define CM_V21_LIMIT UINT64_C(1)

/* Linux GNU x64 only. Entry symbol/signature stays cm_mod_entry_v2.
 * Negotiate the header before reading this optional 2.1 tail; never cast
 * a 2.0 allocation to a 2.1 table. v2.0 DTOs remain exactly 2.0.
 * Host capabilities: bounded count <= 128, each UTF-8 Bytes <= 128.
 */
typedef struct {
    CmHostApiV2 base;
    const CmBytes *capabilities;
    uint64_t capability_count, reserved;
} CmHostApiV21;
typedef struct {
    CmHeader header;
    CmBytes namespace_name, tool, call_id, thread_id, turn_id;
    uint64_t original_limit, reserved;
} CmLimitInputV21;
typedef struct {
    CmHeader header;
    uint64_t decision, limit, reserved;
} CmLimitOutputV21;
typedef uint32_t (*CmLimitHookV21)(void *, const CmLimitInputV21 *,
                                 CmLimitOutputV21 *, CmErrorBuffer *);
typedef struct {
    CmHeader header;
    CmBytes id, capability, resource;
    CmLimitHookV21 callback;
    uint64_t reserved;
} CmLimiterV21;
typedef struct {
    CmModApiV2 base;
    const CmLimiterV21 *limiters;
    uint64_t limiter_count, limiter_stride, reserved;
} CmModApiV21;
/* Header: major=2/minor=1; table <=4096; descriptor stride exactly 72.
 * Combined contributions <=128; declarations must equal the manifest.
 * Input/output/descriptor headers are exact 2.1 sizes (104/32/72).
 * Identity UTF-8 views: namespace/tool/thread/turn <=128, call_id <=512.
 * original_limit is the resolved upstream request before any limiter runs.
 * KEEP requires limit=0 and preserves the original request, including 0.
 * LIMIT requires 1<=limit<=original_limit; multiple limits compose by min.
 * Reserved=0. No Next, retain, async or unwind. All views are borrowed only
 * during this callback. Mod owns userdata, released exactly once by owner.
 * CANCELLED is valid only if Host observed cancellation; invalid output is
 * fatal, never a fallback KEEP or model retry. Error capacity is 1024.
 */
#endif
