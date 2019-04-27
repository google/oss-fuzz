#include "gif_lib.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct gifUserData {
	size_t gifLen;
	uint8_t *gifData;
};


int stub_input_reader (GifFileType *gifFileType, GifByteType *gifByteType, int len);
int fuzz_dgif(const uint8_t *Data, size_t Size);
int fuzz_dgif_extended(const uint8_t *Data, size_t Size);