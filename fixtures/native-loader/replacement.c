#include <stdlib.h>
#include <stdio.h>

__attribute__((constructor)) static void replacement_constructor(void) {
    const char *path = getenv("CM_REPLACEMENT_SENTINEL");
    if (path) {
        FILE *file = fopen(path, "w");
        if (file) { fputs("replacement-executed", file); fclose(file); }
    }
}
/* Deliberately has no cm_mod_entry_v1; also used for post-load missing-entry. */
int cm_replacement_fixture(void) { return 1; }
