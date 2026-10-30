#include "../../crates/cm-abi/include/cm_mod_v22.h"
#include <stddef.h>
#include <stdio.h>
#define SIZE(T, N) _Static_assert(sizeof(T) == N && _Alignof(T) == 8, #T)
#define OFFSET(T, F, N) _Static_assert(offsetof(T, F) == N, #T "." #F)
_Static_assert(CM_RUNTIME_KIND_SAMPLING_BUDGET == 9u, "sampling budget kind");
_Static_assert(CM_SAMPLING_BUDGET == 12u, "sampling budget event");
_Static_assert(CM_RUNTIME_KIND_SUBMIT_REVIEW == 10u, "submit review kind");
_Static_assert(CM_SUBMIT_REVIEW == 13u, "submit review event");
SIZE(CmHandleV22, 16);
OFFSET(CmHandleV22, epoch, 0);
OFFSET(CmHandleV22, slot, 8);
OFFSET(CmHandleV22, generation, 12);
SIZE(CmBufferV22, 24);
OFFSET(CmBufferV22, data, 0);
OFFSET(CmBufferV22, capacity, 8);
OFFSET(CmBufferV22, len, 16);
SIZE(CmRequestV22, 152);
OFFSET(CmRequestV22, header, 0);
OFFSET(CmRequestV22, handle, 8);
OFFSET(CmRequestV22, mod_scope, 24);
OFFSET(CmRequestV22, thread_scope, 40);
OFFSET(CmRequestV22, turn_scope, 56);
OFFSET(CmRequestV22, route, 72);
OFFSET(CmRequestV22, event, 80);
OFFSET(CmRequestV22, reserved, 84);
OFFSET(CmRequestV22, input, 88);
OFFSET(CmRequestV22, thread_id, 104);
OFFSET(CmRequestV22, turn_id, 120);
OFFSET(CmRequestV22, call_id, 136);
SIZE(CmCompletionV22, 48);
OFFSET(CmCompletionV22, header, 0);
OFFSET(CmCompletionV22, request, 8);
OFFSET(CmCompletionV22, status, 24);
OFFSET(CmCompletionV22, flags, 28);
OFFSET(CmCompletionV22, result, 32);
SIZE(CmHostRuntimeApiV22, 56);
OFFSET(CmHostRuntimeApiV22, header, 0);
OFFSET(CmHostRuntimeApiV22, instance, 8);
OFFSET(CmHostRuntimeApiV22, complete, 24);
OFFSET(CmHostRuntimeApiV22, state_get, 32);
OFFSET(CmHostRuntimeApiV22, state_set, 40);
OFFSET(CmHostRuntimeApiV22, reserved, 48);
SIZE(CmModRuntimeApiV22, 40);
OFFSET(CmModRuntimeApiV22, header, 0);
OFFSET(CmModRuntimeApiV22, dispatch, 8);
OFFSET(CmModRuntimeApiV22, cancel, 16);
OFFSET(CmModRuntimeApiV22, request_release, 24);
OFFSET(CmModRuntimeApiV22, reserved, 32);
SIZE(CmRuntimeContributionV22, 72);
OFFSET(CmRuntimeContributionV22, header, 0);
OFFSET(CmRuntimeContributionV22, id, 8);
OFFSET(CmRuntimeContributionV22, capability, 24);
OFFSET(CmRuntimeContributionV22, resource, 40);
OFFSET(CmRuntimeContributionV22, kind, 56);
OFFSET(CmRuntimeContributionV22, reserved, 60);
OFFSET(CmRuntimeContributionV22, route, 64);
SIZE(CmHostApiV22, 88);
OFFSET(CmHostApiV22, base, 0);
OFFSET(CmHostApiV22, runtime, sizeof(CmHostApiV21));
SIZE(CmModApiV22, 136);
OFFSET(CmModApiV22, base, 0);
OFFSET(CmModApiV22, runtime, 96);
OFFSET(CmModApiV22, contributions, 104);
OFFSET(CmModApiV22, contribution_count, 112);
OFFSET(CmModApiV22, contribution_stride, 120);
OFFSET(CmModApiV22, reserved, 128);
int main(void) {
    puts("{\"v22_all_sizes_alignments_offsets\":true,\"unchanged_v21_prefix\":true}");
    return 0;
}
