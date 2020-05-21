#include <stdlib.h>

#include "env-inl.h"
#include "node_crypto.h"
#include "node_crypto_common.h"
#include "node.h"
#include "node_internals.h"
#include "node_url.h"
#include "string_bytes.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    node::url::URL url2((char*)data, size);

    return 0;
} 
