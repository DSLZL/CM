#include "../../crates/cm-abi/include/cm_mod_v23.h"
#include <assert.h>
#include <dlfcn.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

_Static_assert(sizeof(CmHostApiV23) == 96, "Host 2.3");
_Static_assert(offsetof(CmHostApiV23, continuation) == sizeof(CmHostApiV22), "unchanged 2.2 prefix");
_Static_assert(sizeof(CmContinuationApiV23) == 48 && offsetof(CmContinuationApiV23, reserved) == 40, "task services");
_Static_assert(sizeof(CmNextOutputV23) == 40 && offsetof(CmNextOutputV23, result) == 16, "caller output");
_Static_assert(_Alignof(CmNextOutputV23) == 8 && sizeof(CmModApiV23) == 136, "GNU x64 layout");

static uint32_t complete(CmHandleV22 a, const CmCompletionV22 *b, CmErrorBuffer *c) {
    (void)a; (void)b; (void)c; return 0;
}
static uint32_t get(CmHandleV22 a, CmHandleV22 b, CmHandleV22 c, CmBytes d, CmBufferV22 *e, CmErrorBuffer *f) {
    (void)a; (void)b; (void)c; (void)d; (void)e; (void)f; return CM_RUNTIME_NOT_FOUND;
}
static uint32_t set(CmHandleV22 a, CmHandleV22 b, CmHandleV22 c, CmBytes d, CmBytes e, CmErrorBuffer *f) {
    (void)a; (void)b; (void)c; (void)d; (void)e; (void)f; return 0;
}
static uint32_t start(CmHandleV22 a, CmHandleV22 b, CmHandleV22 *c, CmErrorBuffer *d) {
    (void)a; (void)b; (void)c; (void)d; return CM_RUNTIME_INVALID;
}
static uint32_t poll_task(CmHandleV22 a, CmHandleV22 b, CmHandleV22 c, CmNextOutputV23 *d, CmErrorBuffer *e) {
    (void)a; (void)b; (void)c; (void)d; (void)e; return CM_RUNTIME_INVALID;
}
static uint32_t task(CmHandleV22 a, CmHandleV22 b, CmHandleV22 c, CmErrorBuffer *d) {
    (void)a; (void)b; (void)c; (void)d; return CM_RUNTIME_INVALID;
}
typedef uint32_t (*Entry)(const CmHostApiV2 *, const CmHeader **, CmErrorBuffer *);
int main(int argc, char **argv) {
    assert(argc == 3);
    const char *mode = argv[2];
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!library) { fprintf(stderr, "%s\n", dlerror()); return 2; }
    Entry entry = (Entry)dlsym(library, "cm_mod_entry_v2");
    assert(entry);
    CmHostRuntimeApiV22 runtime = {{sizeof(runtime), 2, 2}, {1, 1, 1}, complete, get, set, 0};
    CmContinuationApiV23 continuation = {{sizeof(continuation), 2, 3}, start, poll_task, task, task, 0};
    CmHostApiV23 host = {0};
    host.base.base.base.header = (CmHeader){sizeof(host), 2, 3};
    host.base.runtime = &runtime;
    host.continuation = &continuation;
    const CmHostApiV2 *pointer = &host.base.base.base;
    _Alignas(8) unsigned char misaligned[sizeof(host) + 8];
    if (!strcmp(mode, "major")) host.base.base.base.header.major = 3;
    else if (!strcmp(mode, "minor")) host.base.base.base.header.minor = 4;
    else if (!strcmp(mode, "old-minor")) host.base.base.base.header.minor = 2;
    else if (!strcmp(mode, "short-prefix")) host.base.base.base.header.struct_size = 4;
    else if (!strcmp(mode, "short-tail")) host.base.base.base.header.struct_size = sizeof(CmHostApiV22);
    else if (!strcmp(mode, "huge")) host.base.base.base.header.struct_size = 4097;
    else if (!strcmp(mode, "null-host")) pointer = NULL;
    else if (!strcmp(mode, "misaligned")) { memcpy(misaligned + 1, &host, sizeof(host)); pointer = (const void *)(misaligned + 1); }
    else if (!strcmp(mode, "null-runtime")) host.base.runtime = NULL;
    else if (!strcmp(mode, "runtime-short")) runtime.header.struct_size = 4;
    else if (!strcmp(mode, "runtime-minor")) runtime.header.minor = 3;
    else if (!strcmp(mode, "runtime-reserved")) runtime.reserved = 1;
    else if (!strcmp(mode, "null-complete")) runtime.complete = NULL;
    else if (!strcmp(mode, "null-state-get")) runtime.state_get = NULL;
    else if (!strcmp(mode, "null-state-set")) runtime.state_set = NULL;
    else if (!strcmp(mode, "null-next")) host.continuation = NULL;
    else if (!strcmp(mode, "next-short")) continuation.header.struct_size = 4;
    else if (!strcmp(mode, "next-minor")) continuation.header.minor = 2;
    else if (!strcmp(mode, "next-reserved")) continuation.reserved = 1;
    else if (!strcmp(mode, "null-start")) continuation.start = NULL;
    else if (!strcmp(mode, "null-poll")) continuation.poll = NULL;
    else if (!strcmp(mode, "null-cancel")) continuation.cancel = NULL;
    else if (!strcmp(mode, "null-release")) continuation.release = NULL;
    else assert(!strcmp(mode, "valid"));
    unsigned char storage[CM_ERROR_CAPACITY + 2];
    memset(storage, 0x5a, sizeof(storage));
    CmErrorBuffer error = {storage + 1, CM_ERROR_CAPACITY, 0};
    const CmHeader *table = NULL;
    uint32_t code = entry(pointer, &table, &error);
    assert(storage[0] == 0x5a && storage[sizeof(storage) - 1] == 0x5a);
    assert(error.data == storage + 1 && error.capacity == CM_ERROR_CAPACITY && error.len <= error.capacity);
    if (!strcmp(mode, "valid")) {
        assert(code == 0 && table && table->major == 2 && table->minor == 3 && table->struct_size == sizeof(CmModApiV23));
        const CmModApiV23 *mod = (const void *)table;
        assert(mod->runtime && mod->runtime->header.minor == 2 && mod->runtime->dispatch && mod->runtime->cancel && mod->runtime->request_release);
        assert(mod->contribution_count == 4 && mod->contribution_stride == sizeof(CmRuntimeContributionV22));
        for (size_t index = 0; index < mod->contribution_count; index++) {
            const CmRuntimeContributionV22 *item = &mod->contributions[index];
            assert(item->header.minor == 2 && item->header.struct_size == sizeof(*item) && item->reserved == 0 && item->route == index + 1);
        }
    } else assert(code != 0 && table == NULL);
    printf("{\"status\":\"pass\",\"mode\":\"%s\",\"code\":%u,\"host_size\":%zu,\"services_size\":%zu,\"output_size\":%zu,\"caller_canaries\":true}\n",
        mode, code, sizeof(host), sizeof(continuation), sizeof(CmNextOutputV23));
    assert(dlclose(library) == 0);
    return 0;
}
