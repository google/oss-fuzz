#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "spdk/string.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // convert the data to a string
    char * str = (char *)malloc(Size + 1);
    str[Size] = '\0';
    memcpy(str, Data, Size);

    // fuzz the function
    char ** result = spdk_strarray_from_string(str, ",");

    // free the result
    if (result != NULL) {
        char ** ptr = result;
        while (*ptr != NULL) {
            free(*ptr);
            ptr++;
        }
        free(result);
    }

    // free the string
    free(str);

    return 0;
}
