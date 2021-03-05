#include "dgif_fuzz_common.h"
#include <iostream>

using namespace std;

extern "C" void PrintGifError(int ErrorCode);

int stub_input_reader(GifFileType *gifFileType, GifByteType *gifByteType, int len)
{
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
	if (GifFile != NULL)
	{
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
	if (GifFile == NULL)
	{
		free(gifData);
		return 0;
	}
	if (DGifSlurp(GifFile) != GIF_OK)
	{
		DGifCloseFile(GifFile, &Error);
		free(gifData);
		return 0;
	}
	GraphicsControlBlock gcb;
	for (int i = 0; i < GifFile->ImageCount; i++)
	{
		DGifSavedExtensionToGCB(GifFile, i, &gcb);
	}
	const ColorMapObject *cmap = GifFile->SColorMap;
	if (cmap)
	{
		DGifSavedExtensionToGCB(GifFile, 0, &gcb);
	}
	DGifCloseFile(GifFile, &Error);
	free(gifData);
	return 0;
}

static Color8888 gifColorToColor8888(const GifColorType &color)
{
	return ARGB_TO_COLOR8888(0xff, color.Red, color.Green, color.Blue);
}

static bool willBeCleared(const GraphicsControlBlock &gcb)
{
	return gcb.DisposalMode == DISPOSE_BACKGROUND || gcb.DisposalMode == DISPOSE_PREVIOUS;
}

static long getDelayMs(GraphicsControlBlock &gcb)
{
	return gcb.DelayTime * 10;
}

int fuzz_dgif_ala_android(const uint8_t *Data, size_t Size)
{
	GifFileType *GifFile;
	int Error;
	uint8_t *gifData = (uint8_t *)malloc(Size);
	memcpy(gifData, Data, Size);
	struct gifUserData gUData = {Size, gifData};

	GifFile = DGifOpen((void *)&gUData, stub_input_reader, &Error);
	if (GifFile == NULL)
	{
		free(gifData);
		return 0;
	}

	if (DGifSlurp(GifFile) != GIF_OK)
	{
		PrintGifError(GifFile->Error);
		DGifCloseFile(GifFile, &Error);
		free(gifData);
		return 0;
	}

	long durationMs = 0;
	int lastUnclearedFrame = -1;
	bool *preservedFrames = new bool[GifFile->ImageCount];
	int *restoringFrames = new int[GifFile->ImageCount];
	int loopCount = 0;
	Color8888 bgColor = 0;

	GraphicsControlBlock gcb;
	for (int i = 0; i < GifFile->ImageCount; i++)
	{
		const SavedImage &image = GifFile->SavedImages[i];
		// find the loop extension pair
		for (int j = 0; (j + 1) < image.ExtensionBlockCount; j++)
		{
			ExtensionBlock *eb1 = image.ExtensionBlocks + j;
			ExtensionBlock *eb2 = image.ExtensionBlocks + j + 1;
			if (eb1->Function == APPLICATION_EXT_FUNC_CODE
				// look for "NETSCAPE2.0" app extension
				&& eb1->ByteCount == 11 && !memcmp((const char *)(eb1->Bytes), "NETSCAPE2.0", 11)
				// verify extension contents and get loop count
				&& eb2->Function == CONTINUE_EXT_FUNC_CODE && eb2->ByteCount == 3 && eb2->Bytes[0] == 1)
			{
				loopCount = (int)(eb2->Bytes[2] << 8) + (int)(eb2->Bytes[1]);
			}
		}
		DGifSavedExtensionToGCB(GifFile, i, &gcb);
		// timing
		durationMs += getDelayMs(gcb);
		// preserve logic
		preservedFrames[i] = false;
		restoringFrames[i] = -1;
		if (gcb.DisposalMode == DISPOSE_PREVIOUS && lastUnclearedFrame >= 0)
		{
			preservedFrames[lastUnclearedFrame] = true;
			restoringFrames[i] = lastUnclearedFrame;
		}
		if (!willBeCleared(gcb))
		{
			lastUnclearedFrame = i;
		}
		// Draw
		// assert(y+8 <= Image->ImageDesc.Height);
		// assert(x+8*strlen(legend) <= Image->ImageDesc.Width);
		int imgHeight = GifFile->SavedImages[i].ImageDesc.Height;
		int imgWidth = GifFile->SavedImages[i].ImageDesc.Width;
		// TODO: Source x,y, string, and color from fuzzer input
		int x = 0;
		int y = 0;
		int strLen = 6;
		if (y + 8 <= imgHeight && x + 8 * strLen <= imgWidth)
			GifDrawText8x8(&GifFile->SavedImages[i], 0, 0, "legend", 42);
	}
#if GIF_DEBUG
	ALOGD("FrameSequence_gif created with size %d %d, frames %d dur %ld",
		  GifFile->SWidth, GifFile->SHeight, GifFile->ImageCount, durationMs);
	for (int i = 0; i < GifFile->ImageCount; i++)
	{
		DGifSavedExtensionToGCB(GifFile, i, &gcb);
		ALOGD("    Frame %d - must preserve %d, restore point %d, trans color %d",
			  i, preservedFrames[i], restoringFrames[i], gcb.TransparentColor);
	}
#endif
	const ColorMapObject *cmap = GifFile->SColorMap;
	if (cmap)
	{
		// calculate bg color
		GraphicsControlBlock gcb;
		DGifSavedExtensionToGCB(GifFile, 0, &gcb);
		if (gcb.TransparentColor == NO_TRANSPARENT_COLOR && GifFile->SBackGroundColor < cmap->ColorCount)
		{
			bgColor = gifColorToColor8888(cmap->Colors[GifFile->SBackGroundColor]);
		}
	}

	DGifCloseFile(GifFile, &Error);
	free(gifData);
	delete[] preservedFrames;
	delete[] restoringFrames;
	return 0;
}
