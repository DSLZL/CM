#include <stdio.h>
#include "../../crates/cm-abi/include/cm_mod_v1.h"

int main(void) {
    _Static_assert(sizeof(CmHeader) == 8, "header");
    _Static_assert(sizeof(CmBytes) == 16, "bytes");
    _Static_assert(sizeof(CmErrorBuffer) == 24, "error");
    _Static_assert(sizeof(CmHostApi) == 32, "host");
    _Static_assert(sizeof(CmModApi) == 72, "mod");
    _Static_assert(sizeof(CmPolicyInput) == 96, "input");
    _Static_assert(sizeof(CmPolicyOutput) == 16, "output");
    _Static_assert(_Alignof(CmModApi) == 8, "alignment");
    _Static_assert(offsetof(CmModApi, policy) == 48, "callback offset");
    _Static_assert(offsetof(CmPolicyInput, original_parallel) == 88, "original offset");
    puts("{\"header\":8,\"bytes\":16,\"error\":24,\"host\":32,\"mod\":72,\"input\":96,\"output\":16,\"alignment\":8,\"policy_offset\":48,\"original_offset\":88}");
    return 0;
}
