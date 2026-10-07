#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "egif_fuzz_common.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
	return fuzz_egif(Data, Size);
}