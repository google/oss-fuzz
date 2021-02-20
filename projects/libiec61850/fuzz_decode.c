#include <stdio.h>
#include <stdlib.h>

#include "iec61850_server.h"
#include "hal_thread.h"

int LLVMFuzzerTestOneInput(const char *data, size_t size) {
	int out;
	MmsValue* value = NULL;
	value = MmsValue_decodeMmsData(data, 0, size, &out);
    if (value != NULL) {
        free(value);
	}
    return 0;
}

