#include "gif_lib.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define ARGB_TO_COLOR8888(a, r, g, b) \
	((a) << 24 | (b) << 16 | (g) << 8 | (r))

typedef uint32_t Color8888;

struct gifUserData
{
	size_t gifLen;
	uint8_t *gifData;
};

int stub_input_reader(GifFileType *gifFileType, GifByteType *gifByteType, int len);
int fuzz_dgif(const uint8_t *Data, size_t Size);
int fuzz_dgif_extended(const uint8_t *Data, size_t Size);
int fuzz_dgif_ala_android(const uint8_t *Data, size_t Size);