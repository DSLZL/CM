#ifndef CM_MOD_V1_H
#define CM_MOD_V1_H
#include <stdint.h>
#include <stddef.h>

/* v1: Linux x86_64 GNU only. This is not a native-code sandbox.
 * Every pointer must be aligned and address a valid allocation of its declared
 * size. Host-owned views/output/error storage are borrowed until return only.
 * Bytes are UTF-8, not NUL terminated; null is allowed only for zero length.
 * ID/namespace/tool max 128 bytes, call ID max 512, thread/turn max 128.
 * No Rust objects, private Core addresses, async tasks or retained Host handles.
 * Entry/init run on the startup thread. Policy may run on any OS thread;
 * calls to one Mod are serialized, non-reentrant, synchronous and must finish.
 * Cancellation is checked by Host before/after; a native call is not preemptible.
 * Catch catchable exceptions/panics inside the owner before this C boundary.
 * Abort/segfault/bad pointers can terminate Host; forced exit need not finalize.
 * Allocator ownership never crosses: only Mod release may free Mod userdata.
 * Normal shutdown stops admission, drains calls/tools, releases once; no dlclose.
 */
#define CM_ABI_MAJOR 1
#define CM_ABI_MINOR 0
#define CM_OK 0
#define CM_FAILED 1
#define CM_PANICKED 2
#define CM_KEEP 0
#define CM_FORCE_SERIAL 1
#define CM_ERROR_CAPACITY 1024

typedef struct { uint32_t struct_size; uint16_t major, minor; } CmHeader;
typedef struct { const uint8_t *data; uint64_t len; } CmBytes;
/* Caller owns storage, callee must not replace data/capacity. len <= capacity.
 * Error contents UTF-8; no read of unwritten bytes. Max capacity is 1024.
 */
typedef struct { uint8_t *data; uint64_t capacity, len; } CmErrorBuffer;
typedef struct { CmHeader header; CmBytes capability; uint64_t reserved; } CmHostApi;
typedef struct {
    CmHeader header;
    CmBytes namespace_name, tool, call_id, thread_id, turn_id;
    uint32_t original_parallel, reserved;
} CmPolicyInput;
typedef struct {
    CmHeader header;
    uint32_t decision, reserved;
} CmPolicyOutput;
typedef uint32_t (*CmInit)(void **userdata, CmErrorBuffer *error);
typedef uint32_t (*CmPolicy)(void *userdata, const CmPolicyInput *input,
                             CmPolicyOutput *output, CmErrorBuffer *error);
typedef uint32_t (*CmRelease)(void *userdata, CmErrorBuffer *error);
typedef struct {
    CmHeader header;
    CmBytes mod_id, contribution;
    CmInit init;
    CmPolicy policy;
    CmRelease release;
    uint64_t reserved;
} CmModApi;
/* Read struct_size first, then the complete declared header, then table fields.
 * Minimum v1 table is sizeof(CmModApi). major=1/minor=0.
 * Larger compatible tables may append fields; current fields stay unchanged.
 * All reserved fields zero. init/policy required. Nonnull userdata requires
 * release even if init fails; release uses the same Mod allocator once.
 * All statuses must be OK/FAILED/PANICKED. A failure never falls back to KEEP.
 * Output is caller-provided sizeof(CmPolicyOutput); callee preserves header.
 * Entry returns a Mod-owned, valid table for process lifetime.
 */
uint32_t cm_mod_entry_v1(const CmHostApi *, const CmHeader **, CmErrorBuffer *);
#endif
