#ifndef CM_MOD_V23_H
#define CM_MOD_V23_H
#include "cm_mod_v22.h"
#define CM_TOOL_CONTINUATION_CAPABILITY "core.tool_continuation.v1"
#define CM_RESPONSE_STREAM_CAPABILITY "core.response_stream_observe.v1"
#define CM_CLI_COMMAND_CAPABILITY "cli.command.v1"
#define CM_TUI_COMMAND_CAPABILITY "tui.command.v1"
#define CM_KIND_TOOL_AROUND 12u
#define CM_KIND_TOOL_REPLACEMENT 13u
#define CM_KIND_RESPONSE_STREAM 14u
#define CM_KIND_CLI_COMMAND 15u
#define CM_KIND_TUI_COMMAND 16u
#define CM_TOOL_AROUND 15u
#define CM_STREAM_EVENT 16u
#define CM_CLI_CALL 17u
#define CM_TUI_CALL 18u
#define CM_NEXT_PENDING 3u
typedef struct {
    CmHeader header;
    uint32_t status, reserved;
    CmBufferV22 result;
} CmNextOutputV23;
typedef uint32_t (*CmNextStartV23)(CmHandleV22, CmHandleV22, CmHandleV22 *, CmErrorBuffer *);
typedef uint32_t (*CmNextPollV23)(CmHandleV22, CmHandleV22, CmHandleV22, CmNextOutputV23 *, CmErrorBuffer *);
typedef uint32_t (*CmNextTaskV23)(CmHandleV22, CmHandleV22, CmHandleV22, CmErrorBuffer *);
typedef struct {
    CmHeader header;
    CmNextStartV23 start;
    CmNextPollV23 poll;
    CmNextTaskV23 cancel, release;
    uint64_t reserved;
} CmContinuationApiV23;
typedef struct { CmHostApiV22 base; const CmContinuationApiV23 *continuation; } CmHostApiV23;
typedef CmModApiV22 CmModApiV23;
/* Top-level and continuation headers are exact 2.3; embedded 2.2 tables/DTOs
 * remain 2.2. Start consumes the request's saved continuation once and returns a
 * typed task handle. Poll is nonblocking, repeatable and copies a bounded preview;
 * insufficient capacity leaves the result intact. Cancel signals the original
 * token. Release invalidates task access but retains running work until drained.
 * These services may be called from Mod worker threads. Ordinary dispatch must
 * return before downstream native dispatch can run. QUIESCENT plus a drained
 * child and returned ordinary entries precede request_release. No private Rust
 * value crosses this boundary; the original ToolOutput remains Host-owned. */
#endif
