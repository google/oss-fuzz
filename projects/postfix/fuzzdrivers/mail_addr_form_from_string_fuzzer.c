#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "mail_addr_form.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    char *str = (char *)malloc(Size+1);
    if (!str)
        return 0;
    memcpy(str, Data, Size);
    str[Size] = 0;
    mail_addr_form_from_string(str);
    free(str);
    return 0;
}
