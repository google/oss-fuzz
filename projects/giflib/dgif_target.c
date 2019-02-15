#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include <stdint.h>

#include "gif_lib.h"

struct gifUserData {
	size_t gifLen;
	void *gifData;
};

int stub_input_reader (GifFileType *gifFileType, GifByteType *gifByteType, int len) {
	struct gifUserData *gud = gifFileType->UserData;
	int read_len = (len > gud->gifLen ? gud->gifLen : len);
	memcpy(gifByteType, gud->gifData, read_len);
	return read_len;
}

void sponge(GifFileType *GifFileIn, int *ErrorCode) {
	GifFileType *GifFileOut = (GifFileType *)NULL;
	if ((GifFileOut = EGifOpenFileHandle(1, ErrorCode)) == NULL) {
		return;
	}

	/*
	 * Your operations on in-core structures go here.
	 * This code just copies the header and each image from the incoming file.
	 */
	GifFileOut->SWidth = GifFileIn->SWidth;
	GifFileOut->SHeight = GifFileIn->SHeight;
	GifFileOut->SColorResolution = GifFileIn->SColorResolution;
	GifFileOut->SBackGroundColor = GifFileIn->SBackGroundColor;
	if (GifFileIn->SColorMap) {
		GifFileOut->SColorMap = GifMakeMapObject(
				GifFileIn->SColorMap->ColorCount,
				GifFileIn->SColorMap->Colors);
	} else {
		GifFileOut->SColorMap = NULL;
	}

	for (int i = 0; i < GifFileIn->ImageCount; i++)
		(void) GifMakeSavedImage(GifFileOut, &GifFileIn->SavedImages[i]);

	// We ignore error since it is irrelevant in the context of this
	// test harness.
	EGifSpew(GifFileOut);
	return;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
	GifFileType *GifFile;
	int Error;
	void *gifData = malloc(Size);
	memcpy(gifData, (void *)Data, Size);
	struct gifUserData gUData = {Size, gifData};

	GifFile = DGifOpen((void *)&gUData, stub_input_reader, &Error);
	if (GifFile == NULL){
		goto freebuf;
	}
	if (DGifSlurp(GifFile) == GIF_ERROR) {
		goto cleanup;
	}
	sponge(GifFile, &Error);

cleanup:
	DGifCloseFile(GifFile, &Error);
freebuf:
	free(gifData);
	return 0;
}