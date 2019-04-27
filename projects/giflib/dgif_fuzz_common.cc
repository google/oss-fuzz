#include "dgif_fuzz_common.h"

int stub_input_reader (GifFileType *gifFileType, GifByteType *gifByteType, int len) {
	struct gifUserData *gud = (struct gifUserData *)gifFileType->UserData;
	if (gud->gifLen == 0)
		return 0;
	int read_len = (len > gud->gifLen ? gud->gifLen : len);
	memcpy(gifByteType, gud->gifData, read_len);
	gud->gifData += read_len;
	gud->gifLen -= read_len;
	return read_len;
}

int fuzz_dgif(const uint8_t *Data, size_t Size)
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

int fuzz_dgif_extended(const uint8_t *Data, size_t Size)
{
	GifFileType *GifFile;
	int Error;
	uint8_t *gifData = (uint8_t *)malloc(Size);
	memcpy(gifData, Data, Size);
	struct gifUserData gUData = {Size, gifData};

	GifFile = DGifOpen((void *)&gUData, stub_input_reader, &Error);
	if (GifFile == NULL){
		free(gifData);
		return 0;
	}
	if(DGifSlurp(GifFile) != GIF_OK){
		DGifCloseFile(GifFile, &Error);
		free(gifData);
		return 0;
	}
    GraphicsControlBlock gcb;
    for (int i = 0; i < GifFile->ImageCount; i++) {
        DGifSavedExtensionToGCB(GifFile, i, &gcb);
    }
    for (int i = 0; i < GifFile->ImageCount; i++) {
        DGifSavedExtensionToGCB(GifFile, i, &gcb);
    }
    const ColorMapObject* cmap = GifFile->SColorMap;
    if (cmap) {
        DGifSavedExtensionToGCB(GifFile, 0, &gcb);
    }
	DGifCloseFile(GifFile, &Error);
	free(gifData);
	return 0;
}