#include "../../crates/cm-abi/include/cm_mod_v21.h"
#include <stddef.h>
#include <stdio.h>
#define SIZE(T, N) _Static_assert(sizeof(T) == (N), #T " size"); _Static_assert(_Alignof(T) == 8, #T " align")
#define OFFSET(T, F, N) _Static_assert(offsetof(T, F) == (N), #T "." #F)
SIZE(CmHostApiV21, 80);
OFFSET(CmHostApiV21, base, 0);
OFFSET(CmHostApiV21, capabilities, 56);
OFFSET(CmHostApiV21, capability_count, 64);
OFFSET(CmHostApiV21, reserved, 72);
SIZE(CmModApiV21, 96);
OFFSET(CmModApiV21, base, 0);
OFFSET(CmModApiV21, limiters, 64);
OFFSET(CmModApiV21, limiter_count, 72);
OFFSET(CmModApiV21, limiter_stride, 80);
OFFSET(CmModApiV21, reserved, 88);
SIZE(CmLimiterV21, 72);
OFFSET(CmLimiterV21, header, 0);
OFFSET(CmLimiterV21, id, 8);
OFFSET(CmLimiterV21, capability, 24);
OFFSET(CmLimiterV21, resource, 40);
OFFSET(CmLimiterV21, callback, 56);
OFFSET(CmLimiterV21, reserved, 64);
SIZE(CmLimitInputV21, 104);
OFFSET(CmLimitInputV21, header, 0);
OFFSET(CmLimitInputV21, namespace_name, 8);
OFFSET(CmLimitInputV21, tool, 24);
OFFSET(CmLimitInputV21, call_id, 40);
OFFSET(CmLimitInputV21, thread_id, 56);
OFFSET(CmLimitInputV21, turn_id, 72);
OFFSET(CmLimitInputV21, original_limit, 88);
OFFSET(CmLimitInputV21, reserved, 96);
SIZE(CmLimitOutputV21, 32);
OFFSET(CmLimitOutputV21, header, 0);
OFFSET(CmLimitOutputV21, decision, 8);
OFFSET(CmLimitOutputV21, limit, 16);
OFFSET(CmLimitOutputV21, reserved, 24);
int main(void) { puts("{\"v21_all_sizes_alignments_offsets\":true}"); }
