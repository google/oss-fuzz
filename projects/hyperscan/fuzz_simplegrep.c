#include "hs.h"

#include <stdint.h>
#include <string.h>
#include <stdio.h>

FILE * logfile = NULL;
hs_scratch_t *scratch = NULL;
void * scrachAllocArea = NULL;
size_t scrachAllocSize = 0;

static int eventHandler(unsigned int id, unsigned long long from,
                        unsigned long long to, unsigned int flags, void *ctx) {
    fprintf(logfile, "Match for pattern \"%s\" at offset %llu\n", (char *)ctx, to);
    return 0;
}

static void * fuzz_scratch_alloc(size_t size) {
    if (size > scrachAllocSize) {
        scrachAllocArea = realloc(scrachAllocArea, size);
        scrachAllocSize = size;
    }
    return scrachAllocArea;
}

static void fuzz_nofree(void * area) {
    fprintf(logfile, "free\n");
    return;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {

    if (logfile == NULL) {
        //use custom allocator to avoir reallocating at each run
        //hs_set_scratch_allocator(fuzz_scratch_alloc, fuzz_nofree);
        logfile = fopen("/dev/null", "wb");
    }
    //decompose into needle and haystack
    const uint8_t * haystack = memchr(Data, 0, Size);
    if (haystack == NULL) {
        return 0;
    }
    haystack++;
    Size -= (haystack - Data);

    hs_database_t *database;
    hs_compile_error_t *compile_err;
    if (hs_compile(Data, HS_FLAG_DOTALL, HS_MODE_BLOCK, NULL, &database,
                   &compile_err) != HS_SUCCESS) {
        fprintf(logfile, "ERROR: Unable to compile pattern \"%s\": %s\n",
                Data, compile_err->message);
        hs_free_compile_error(compile_err);
        return 0;
    }

    if (hs_alloc_scratch(database, &scratch) != HS_SUCCESS) {
        fprintf(logfile, "ERROR: Unable to allocate scratch space. Exiting.\n");
        hs_free_database(database);
        return 0;
    }
    
    if (hs_scan(database, haystack, Size, 0, scratch, eventHandler,
                Data) != HS_SUCCESS) {
        fprintf(logfile, "ERROR: Unable to scan input buffer. Exiting.\n");
        hs_free_database(database);
        return 0;
    }

    hs_free_database(database);
    return 0;
}
