#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "gif_lib.h"

struct gifUserData {
	size_t gifLen;
	uint8_t *gifData;
};

int stub_input_reader (GifFileType *gifFileType, GifByteType *gifByteType, int len) {
	struct gifUserData *gud = gifFileType->UserData;
	if (gud->gifLen == 0)
		return 0;
	int read_len = (len > gud->gifLen ? gud->gifLen : len);
	memcpy(gifByteType, gud->gifData, read_len);
	gud->gifData += read_len;
	gud->gifLen -= read_len;
	return read_len;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
	GifFileType *GifFile;
	int Error;
	uint8_t *gifData = (uint8_t *)malloc(Size);
	memcpy(gifData, Data, Size);
	struct gifUserData gUData = {Size, gifData};

	GifFile = DGifOpen((void *)&gUData, stub_input_reader, &Error);
	if (GifFile != NULL) {
		DGifSlurp(GifFile);
		DGifCloseFile(GifFile, &Error);
	}
	free(gifData);
	return 0;
}