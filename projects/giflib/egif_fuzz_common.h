#include "gif_lib.h"
#include "assert.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct gifUserData
{
	size_t gifLen;
	size_t allocatedSize;
	uint8_t *gifData;
};

extern "C" int GifQuantizeBuffer(unsigned int Width, unsigned int Height,
                   int *ColorMapSize, GifByteType * RedInput,
                   GifByteType * GreenInput, GifByteType * BlueInput,
                   GifByteType * OutputBuffer,
                   GifColorType * OutputColorMap);

int stub_output_writer(GifFileType *gifFileType, GifByteType *gifByteType, int len);
int fuzz_egif(const uint8_t *Data, size_t Size);
