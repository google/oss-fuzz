#include <stddef.h>
#include <stdint.h>

#include "fuzzer_temp_file.h"
#include "tidy.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    TidyDoc tdoc = tidyCreate();

    char* tmpfile = fuzzer_get_tmpfile(data, size);
    tidyLoadConfig(tdoc, tmpfile);
    fuzzer_release_tmpfile(tmpfile);
    tidyRelease(tdoc);
    return 0;
}
