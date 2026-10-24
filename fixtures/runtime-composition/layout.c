#include <stddef.h>
#include <stdio.h>
#include "../../crates/cm-abi/include/cm_mod_v2.h"

#define SIZE(T, N) _Static_assert(sizeof(T) == (N), #T)
#define ALIGN(T, N) _Static_assert(_Alignof(T) == (N), #T " alignment")
#define OFFSET(T, F, N) _Static_assert(offsetof(T, F) == (N), #T "." #F)

SIZE(CmHeader, 8);
SIZE(CmBytes, 16);
SIZE(CmErrorBuffer, 24);
SIZE(CmHostApi, 32);
SIZE(CmModApi, 72);
SIZE(CmPolicyInput, 96);
SIZE(CmPolicyOutput, 16);
SIZE(CmDecisionV2, 16);
SIZE(CmHostApiV2, 56);
SIZE(CmResourceV2, 32);
SIZE(CmInitContextV2, 48);
SIZE(CmInputV2, 128);
SIZE(CmContributionV2, 72);
SIZE(CmModApiV2, 64);
ALIGN(CmDecisionV2, 4);
ALIGN(CmHostApiV2, 8);
ALIGN(CmResourceV2, 8);
ALIGN(CmInitContextV2, 8);
ALIGN(CmInputV2, 8);
ALIGN(CmContributionV2, 8);
ALIGN(CmModApiV2, 8);
OFFSET(CmDecisionV2, decision, 8);
OFFSET(CmDecisionV2, reserved, 12);
OFFSET(CmHostApiV2, capability, 8);
OFFSET(CmHostApiV2, host_build_id, 24);
OFFSET(CmHostApiV2, next, 40);
OFFSET(CmHostApiV2, reserved, 48);
OFFSET(CmResourceV2, content, 16);
OFFSET(CmInitContextV2, resources, 8);
OFFSET(CmInitContextV2, resource_count, 16);
OFFSET(CmInitContextV2, config, 24);
OFFSET(CmInitContextV2, reserved, 40);
OFFSET(CmInputV2, policy, 8);
OFFSET(CmInputV2, phase, 104);
OFFSET(CmInputV2, outcome, 108);
OFFSET(CmInputV2, decision, 112);
OFFSET(CmInputV2, reserved, 116);
OFFSET(CmInputV2, next_token, 120);
OFFSET(CmContributionV2, id, 8);
OFFSET(CmContributionV2, capability, 24);
OFFSET(CmContributionV2, resource, 40);
OFFSET(CmContributionV2, kind, 56);
OFFSET(CmContributionV2, reserved, 60);
OFFSET(CmContributionV2, callback, 64);
OFFSET(CmModApiV2, mod_id, 8);
OFFSET(CmModApiV2, contributions, 24);
OFFSET(CmModApiV2, contribution_count, 32);
OFFSET(CmModApiV2, init, 40);
OFFSET(CmModApiV2, release, 48);
OFFSET(CmModApiV2, reserved, 56);

int main(void) {
    puts("{\"v1_preserved\":true,\"v2_all_sizes_alignments_offsets\":true}");
    return 0;
}
