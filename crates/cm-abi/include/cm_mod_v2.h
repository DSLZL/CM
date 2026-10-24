#ifndef CM_MOD_V2_H
#define CM_MOD_V2_H
#include "cm_mod_v1.h"

/* Linux GNU x64 composition ABI 2.0; v1 declarations are unchanged.
 * Views/contexts are borrowed for the synchronous call only. Valid native
 * allocations are required; this protocol is not a memory sandbox.
 * Original Core eligibility is computed before this policy chain.
 * Next advances policies, never the asynchronous tool handler.
 */
#define CM_V2_MAJOR 2
#define CM_V2_MINOR 0
#define CM_V2_CAPABILITY "core.tool_parallel_eligibility.compose.v1"
#define CM_V2_CANCELLED 3
#define CM_V2_BEFORE 1
#define CM_V2_AROUND 2
#define CM_V2_REPLACEMENT 3
#define CM_V2_AFTER 4
#define CM_V2_SUCCEEDED 0
#define CM_V2_FAILED 1
#define CM_V2_CANCELLED_OUTCOME 2

typedef struct {
    CmHeader header;
    uint32_t decision, reserved;
} CmDecisionV2;
typedef uint32_t (*CmNextV2)(uint64_t token, CmDecisionV2 *output,
                            CmErrorBuffer *error);
typedef struct {
    CmHeader header;
    CmBytes capability, host_build_id;
    CmNextV2 next;
    uint64_t reserved;
} CmHostApiV2;
/* path is UTF-8; content is raw bounded bytes, unlike textual v1 views. */
typedef struct { CmBytes path, content; } CmResourceV2;
typedef struct {
    CmHeader header;
    const CmResourceV2 *resources;
    uint64_t resource_count;
    CmBytes config;
    uint64_t reserved;
} CmInitContextV2;
typedef struct {
    CmHeader header;
    CmPolicyInput policy; /* nested v1 header stays 1.0 */
    uint32_t phase, outcome, decision, reserved;
    uint64_t next_token;
} CmInputV2;
typedef uint32_t (*CmHookV2)(void *, const CmInputV2 *, CmDecisionV2 *,
                            CmErrorBuffer *);
typedef uint32_t (*CmInitV2)(const CmInitContextV2 *, void **, CmErrorBuffer *);
typedef struct {
    CmHeader header;
    CmBytes id, capability, resource;
    uint32_t kind, reserved;
    CmHookV2 callback;
} CmContributionV2;
typedef struct {
    CmHeader header;
    CmBytes mod_id;
    const CmContributionV2 *contributions;
    uint64_t contribution_count;
    CmInitV2 init;
    CmRelease release;
    uint64_t reserved;
} CmModApiV2;

/* Read bounded size/header before the complete table. Exactly 2.0.
 * entry returns a valid descriptor array which the Host copies before init.
 * Descriptor stride/struct_size is exactly sizeof(CmContributionV2).
 * Actual IDs/capabilities/kinds/resources must equal the manifest, with no extras.
 * init returns Mod-owned userdata; nonnull userdata requires release.
 * before/after: no Next, output KEEP. around: Next at most once; no Next
 * requires FORCE_SERIAL. Downstream FORCE_SERIAL and failures are latched.
 * replacement: no Next, KEEP or FORCE_SERIAL, exclusive before loading.
 * Next is scoped to this callback/owner/OS thread; no retain or async use.
 * Next output needs its exact 2.0 header and reserved=0; its error storage
 * must be nonnull with capacity=CM_ERROR_CAPACITY and len<=capacity.
 * CANCELLED is valid only when the Host observed cancellation.
 * No unwind across C; abort/segfault/stuck callbacks can terminate the Host.
 */
uint32_t cm_mod_entry_v2(const CmHostApiV2 *, const CmHeader **, CmErrorBuffer *);
#endif
