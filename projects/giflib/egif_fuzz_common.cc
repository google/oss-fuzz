#include "egif_fuzz_common.h"
#define GIF_IMAGE_WIDTH 100
// This is rgb byte stream length per horizontal line = GIF_IMAGE_WIDTH * 3
#define GIF_IMAGE_LINE 300

extern "C" void PrintGifError(int ErrorCode);

int stub_output_writer(GifFileType *gifFileType, const uint8_t *buf, int len)
{
	struct gifUserData *gud = (struct gifUserData *)gifFileType->UserData;

	if (gud == NULL || gud->gifData == NULL || len == 0)
		return 0;
	if (gud->allocatedSize < (gud->gifLen + len))
	{
		// Reallocate gifFileType
		int newSize = (gud->gifLen + len) * 2;
		uint8_t *oldGud = gud->gifData;
		gud->gifData = (uint8_t *)realloc(oldGud, newSize);
		// Assert when realloc fails.
		assert(gud->gifData != NULL);
		gud->allocatedSize = newSize;
	}
	memcpy(gud->gifData + gud->gifLen, buf, len);
	gud->gifLen += len;
	return len;
}

// RGB to GIF converter
static bool rgb_to_gif(const uint8_t *data, size_t size)
{
	// Bail if total size is not a multiple of GIF_IMAGE_LINE (see below)
	// Keep a fixed width e.g., GIF_IMAGE_WIDTH
	// size/3 = GIF_IMAGE_WIDTH * height
	// height = size/GIF_IMAGE_LINE

	// Extract height
	int height = size / GIF_IMAGE_LINE;

	// GifByteType is unsigned char (raw byte)
	// mem holds the raw RGB byte stream for the entire image
	GifByteType *mem = (GifByteType *)malloc(sizeof(GifByteType) * height * GIF_IMAGE_WIDTH * 3);
	if (!mem)
		return false;

	// Copy RGB data to mem
	memcpy(mem, data, size);

	GifByteType *red_buf = mem;
	GifByteType *green_buf = mem + (GIF_IMAGE_WIDTH * height);
	GifByteType *blue_buf = mem + (GIF_IMAGE_WIDTH * height * 2);

	// ColorMapObject *GifMakeMapObject(int ColorCount, GifColorType *ColorMap)
	// Allocate storage for a color map object with the given number of RGB triplet slots.
	// If the second argument is non-NULL, initialize the color table portion of
	// the new map from it. Returns NULL if memory is exhausted or if the size is
	// not a power of 2 <= 256.
	// TODO: Fuzz color map size (has to be a power of 2 less than equal to 256)
	// TODO: Fuzz color table initialization
	int color_map_size = 256;
	ColorMapObject *output_color_map = GifMakeMapObject(color_map_size, NULL);
	if (!output_color_map)
	{
		free(mem);
		return false;
	}

	// gif output will be written to output_buf
	size_t out_size = sizeof(GifByteType) * GIF_IMAGE_WIDTH * height;
	GifByteType *output_buf = (GifByteType *)malloc(out_size);
	if (!output_buf)
	{
		GifFreeMapObject(output_color_map);
		free(mem);
		return false;
	}

	if (GifQuantizeBuffer(GIF_IMAGE_WIDTH, height, &color_map_size,
						  red_buf, green_buf, blue_buf,
						  output_buf, output_color_map->Colors) == GIF_ERROR)
	{
		GifFreeMapObject(output_color_map);
		free(output_buf);
		free(mem);
		return false;
	}

	// Now that raw RGB data has been quantized, we no longer need it.
	free(mem);

	GifFileType *GifFile;
	int Error;
	// We start with 1024, but resize dynamically
	// see stub_output_writer
	uint8_t *gifData = (uint8_t *)malloc(1024);
	struct gifUserData gUData = {0, 1024, gifData};

	/* GifFileType *EGifOpen(void *userPtr, OutputFunc writeFunc, int *ErrorCode)
	 * Description:
	 *  Open a new GIF file using the given userPtr (in binary mode, if under Windows).
	 *  writeFunc is a function pointer that writes to output gif file.
	 *  If any error occurs, NULL is returned and the ErrorCode is set.
	 */
	GifFile = EGifOpen((void *)&gUData, stub_output_writer, &Error);
	if (GifFile == NULL)
	{
		PrintGifError(GifFile->Error);
		GifFreeMapObject(output_color_map);
		free(output_buf);
		free(gUData.gifData);
		return false;
	}

	/* void EGifSetGifVersion(GifFileType *GifFile, bool gif89)
	 * Description:
	 * 	Set the GIF type, to GIF89 if the argument is true and GIF87 if it is false.
	 * 	The default type is GIF87. This function may be called after the GifFile
	 * 	record is allocated but before EGifPutScreenDesc().
	 */
	EGifSetGifVersion(GifFile, false);

	/* int EGifPutScreenDesc(GifFileType *GifFile,
     *   const int GifWidth, const GifHeight,
     *   const int GifColorRes, const int GifBackGround,
     *   ColorMapObject *GifColorMap)
     *
	 *  Update the GifFile Screen parameters, in GifFile structure and in the real file.
	 *  If error occurs, returns GIF_ERROR (see gif_lib.h), otherwise GIF_OK.
	 * 	This routine should be called immediately after the GIF file was opened.
	 */
	if (EGifPutScreenDesc(GifFile, GIF_IMAGE_WIDTH, height, color_map_size, 0, output_color_map) == GIF_ERROR)
	{
		PrintGifError(GifFile->Error);
		GifFreeMapObject(output_color_map);
		free(output_buf);
		EGifCloseFile(GifFile, &Error);
		free(gUData.gifData);
		return false;
	}

	/* int EGifPutImageDesc(GifFileType *GifFile, const int GifLeft, const int GifTop,
	 * const int GifWidth, const GifHeight, const bool GifInterlace, ColorMapObject *GifColorMap)
	 * Description
	 *  Update GifFile Image parameters, in GifFile structure and in the real file.
	 *  if error occurs returns GIF_ERROR (see gif_lib.h), otherwise GIF_OK.
	 *  This routine should be called each time a new image must be dumped to the file.
	 */
	if (EGifPutImageDesc(GifFile, 0, 0, GIF_IMAGE_WIDTH, height, false, NULL) == GIF_ERROR)
	{
		PrintGifError(GifFile->Error);
		GifFreeMapObject(output_color_map);
		free(output_buf);
		EGifCloseFile(GifFile, &Error);
		free(gUData.gifData);
		return false;
	}

	GifByteType *output_bufp = output_buf;
	for (int i = 0; i < height; i++)
	{
		/* int EGifPutLine(GifFileType *GifFile, PixelType *GifLine, int GifLineLen)
		 * Description:
		 *  Dumps a block of pixels out to the GIF file. The slab can be of any length.
		 *  More than that, this routine may be interleaved with EGifPutPixel(),
		 *  until all pixels have been sent.
		 *  Returns GIF_ERROR if something went wrong, GIF_OK otherwise.
		 */
		if (EGifPutLine(GifFile, output_bufp, GIF_IMAGE_WIDTH) == GIF_ERROR)
		{
			PrintGifError(GifFile->Error);
			GifFreeMapObject(output_color_map);
			free(output_buf);
			EGifCloseFile(GifFile, &Error);
			free(gUData.gifData);
			return false;
		}
		output_bufp += GIF_IMAGE_WIDTH;
	}

	/* void GifFreeMapObject(ColorMapObject *Object)
	 * Description
	 *  Free the storage occupied by a ColorMapObject that is no longer needed.
	 */
	GifFreeMapObject(output_color_map);
	free(output_buf);
	EGifCloseFile(GifFile, &Error);
	free(gUData.gifData);
	return true;
}

int fuzz_egif(const uint8_t *Data, size_t Size)
{
	// We treat fuzzed data as a raw RGB stream for a picture
	// with a fixed width of GIF_IMAGE_WIDTH.
	// Since we need 3 color bytes per pixel (RGB), height = size/GIF_IMAGE_LINE
	//      where GIF_IMAGE_LINE = GIF_IMAGE_WIDTH * 3
	// For integral height, we need Size to be a multiple of GIF_IMAGE_LINE
	if ((Size == 0) || ((Size % GIF_IMAGE_LINE) != 0))
		return 0;
	bool status = rgb_to_gif(Data, Size);
	return 0;
}
