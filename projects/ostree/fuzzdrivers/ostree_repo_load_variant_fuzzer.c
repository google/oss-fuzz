#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "ostree.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    GError *error = NULL;
    GVariant *variant = NULL;
    g_autoptr(OstreeRepo) repo = NULL;
    g_autofree char *sha256 = NULL;
    repo = ostree_repo_new(NULL);
    sha256 = g_compute_checksum_for_data(G_CHECKSUM_SHA256, Data, Size);
    if (ostree_repo_load_variant(repo, OSTREE_OBJECT_TYPE_COMMIT, sha256, &variant, &error))
        g_variant_unref(variant);
    return 0;
}
