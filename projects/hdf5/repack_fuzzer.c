#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "h5tools.h"
#include "h5tools_utils.h"
#include "h5repack.h"

#define PROGRAMNAME "h5repack"

extern "C"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size){
    char *payload = (char *)malloc(size+1);
    if (payload == NULL){
            return 0;
    }
    memcpy(payload, data, size);
    payload[size] = '\0';
    
    pack_opt_t pack_options;
    HDmemset(&pack_options, 0, sizeof(pack_opt_t));

    h5tools_init();
    h5tools_setprogname(PROGRAMNAME);
    if (h5repack_init(&pack_options, 0, FALSE) < 0) {
        h5tools_close();
        return 1;
    }
    
    if (h5repack_addfilter(payload, &pack_options) < 0) {
        h5repack_end(&pack_options);
        h5tools_close();
        return 1;
    }

    
    h5repack_end(&pack_options);
    free(payload);
    h5tools_close();
    return 0;
}
~