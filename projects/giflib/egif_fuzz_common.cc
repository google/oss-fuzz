#include "egif_fuzz_common.h"

//using namespace std;

extern "C" void PrintGifError(int ErrorCode);

int stub_output_writer (GifFileType *gifFileType, const uint8_t *buf, int len) {
	struct gifUserData *gud = (struct gifUserData *)gifFileType->UserData;

	if (gud == NULL || gud->gifData == NULL || len == 0)
		return 0;

	memcpy(gud->gifData, buf, len);
	gud->gifData += len;
	gud->gifLen += len;
	return len;
}

int fuzz_egif(const uint8_t *Data, size_t Size)
{
	GifFileType *GifFile;
	int Error;
	uint8_t *gifData = (uint8_t *)malloc(Size);
	memcpy(gifData, Data, Size);
	struct gifUserData gUData = {Size, gifData};

	GifFile = EGifOpen((void *)&gUData, stub_output_writer, &Error);
	if (GifFile == NULL) {
		PrintGifError(GifFile->Error);
		free(gifData);
		return 0;
	}

	EGifCloseFile(GifFile, &Error);
	free(gifData);
	return 0;
}