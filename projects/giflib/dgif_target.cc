#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "dgif_fuzz_common.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
	return fuzz_dgif_extended(Data, Size);
}