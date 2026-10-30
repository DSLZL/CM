#ifndef CM_MOD_V22_H
#define CM_MOD_V22_H
#include "cm_mod_v21.h"
#define CM_RUNTIME_LIFECYCLE "runtime.lifecycle.v1"
#define CM_RUNTIME_TOOL "runtime.tool.v1"
#define CM_RUNTIME_CONTEXT_SECTION "runtime.context_section.v1"
#define CM_SAMPLING_BUDGET_CAPABILITY "core.turn_sampling_budget.v1"
#define CM_SUBMIT_REVIEW_CAPABILITY "tui.submit_review.v1"
#define CM_RUNTIME_KIND_LIFECYCLE 6u
#define CM_RUNTIME_KIND_TOOL 7u
#define CM_RUNTIME_KIND_CONTEXT_SECTION 8u
#define CM_RUNTIME_KIND_SAMPLING_BUDGET 9u
#define CM_RUNTIME_KIND_SUBMIT_REVIEW 10u
#define CM_THREAD_START 1u
#define CM_THREAD_READY 2u
#define CM_THREAD_RESUME 3u
#define CM_THREAD_IDLE 4u
#define CM_THREAD_STOP 5u
#define CM_TURN_START 6u
#define CM_TURN_STOP 7u
#define CM_TURN_ABORT 8u
#define CM_TURN_ERROR 9u
#define CM_TOOL_CALL 10u
#define CM_SECTION 11u
#define CM_SAMPLING_BUDGET 12u
#define CM_SUBMIT_REVIEW 13u
#define CM_RUNTIME_SUCCEEDED 0u
#define CM_RUNTIME_FAILED 1u
#define CM_RUNTIME_CANCELLED 2u
#define CM_RUNTIME_QUIESCENT 1u
#define CM_RUNTIME_INVALID 4u
#define CM_RUNTIME_STALE 5u
#define CM_RUNTIME_WRONG_OWNER 6u
#define CM_RUNTIME_ALREADY_COMPLETED 7u
#define CM_RUNTIME_REQUEST_CANCELLED 8u
#define CM_RUNTIME_LIMIT 9u
#define CM_RUNTIME_NOT_FOUND 10u
#define CM_RUNTIME_REENTRANT 11u
#define CM_RUNTIME_MAX_INPUT 65536u
#define CM_RUNTIME_MAX_RESULT 262144u
#define CM_RUNTIME_MAX_STATE 1048576u
#define CM_RUNTIME_MAX_MOD_REQUESTS 64u
#define CM_RUNTIME_MAX_REQUESTS 1024u
#define CM_RUNTIME_MAX_SCOPES 4096u
typedef struct { uint64_t epoch; uint32_t slot, generation; } CmHandleV22;
typedef struct { uint8_t *data; uint64_t capacity, len; } CmBufferV22;
typedef struct {
    CmHeader header;
    CmHandleV22 handle, mod_scope, thread_scope, turn_scope;
    uint64_t route;
    uint32_t event, reserved;
    CmBytes input, thread_id, turn_id, call_id;
} CmRequestV22;
typedef struct {
    CmHeader header;
    CmHandleV22 request;
    uint32_t status, flags;
    CmBytes result;
} CmCompletionV22;
typedef uint32_t (*CmCompleteV22)(CmHandleV22, const CmCompletionV22 *, CmErrorBuffer *);
typedef uint32_t (*CmStateGetV22)(CmHandleV22, CmHandleV22, CmHandleV22, CmBytes, CmBufferV22 *, CmErrorBuffer *);
typedef uint32_t (*CmStateSetV22)(CmHandleV22, CmHandleV22, CmHandleV22, CmBytes, CmBytes, CmErrorBuffer *);
typedef struct {
    CmHeader header;
    CmHandleV22 instance;
    CmCompleteV22 complete;
    CmStateGetV22 state_get;
    CmStateSetV22 state_set;
    uint64_t reserved;
} CmHostRuntimeApiV22;
typedef uint32_t (*CmDispatchV22)(void *, const CmRequestV22 *, CmErrorBuffer *);
typedef uint32_t (*CmCancelV22)(void *, CmHandleV22, CmErrorBuffer *);
typedef uint32_t (*CmRequestReleaseV22)(void *, CmHandleV22, CmErrorBuffer *);
typedef struct {
    CmHeader header;
    CmDispatchV22 dispatch;
    CmCancelV22 cancel;
    CmRequestReleaseV22 request_release;
    uint64_t reserved;
} CmModRuntimeApiV22;
typedef struct {
    CmHeader header;
    CmBytes id, capability, resource;
    uint32_t kind, reserved;
    uint64_t route;
} CmRuntimeContributionV22;
typedef struct { CmHostApiV21 base; const CmHostRuntimeApiV22 *runtime; } CmHostApiV22;
typedef struct {
    CmModApiV21 base;
    const CmModRuntimeApiV22 *runtime;
    const CmRuntimeContributionV22 *contributions;
    uint64_t contribution_count, contribution_stride, reserved;
} CmModApiV22;
/* Dispatch admits a request; complete copies the result synchronously. QUIESCENT
 * also acknowledges no future access to request/scopes, including after cancel.
 * Host waits for every ordinary entry to return before request_release, exactly
 * once. No buffer, Future, Waker, Rust object or allocator ownership crosses ABI.
 * Ordinary Mod entries are serialized per Mod. Complete/state services may run
 * on Mod threads; ordinary entry reentrancy is forbidden. Libraries stay pinned.
 * Cancelled/duplicate complete can acknowledge quiescence but cannot redeliver.
 * All 2.2 DTO headers use exact sizeof, major=2, minor=2, reserved=0. */
#endif
