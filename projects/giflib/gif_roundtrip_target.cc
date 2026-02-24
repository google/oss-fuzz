// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////
// Comprehensive GIF roundtrip fuzzer targeting uncovered code paths:
// - Decode-encode roundtrip via DGifSlurp + EGifSpew + GifMakeSavedImage
// - Low-level decode API (DGifGetLine, DGifGetPixel, DGifGetCode)
// - Encode with extensions (EGifPutComment, EGifPutExtension*, EGifPutPixel)
// - Utility functions (GifUnionColorMap, GifBitSize, GifApplyTranslation)
// - Drawing functions (GifDrawBox, GifDrawRectangle, GifDrawBoxedText8x8)
// - GCB roundtrip (DGifExtensionToGCB, EGifGCBToExtension, EGifGCBToSavedExtension)
// - Error strings (GifErrorString)

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "gif_lib.h"

struct MemReader {
	const uint8_t *data;
	size_t len;
	size_t pos;
};

static int mem_read(GifFileType *gif, GifByteType *buf, int len)
{
	struct MemReader *r = (struct MemReader *)gif->UserData;
	size_t avail = r->len - r->pos;
	if (avail == 0) return 0;
	size_t toRead = (size_t)len < avail ? (size_t)len : avail;
	memcpy(buf, r->data + r->pos, toRead);
	r->pos += toRead;
	return (int)toRead;
}

struct MemWriter {
	uint8_t *data;
	size_t len;
	size_t cap;
};

static int mem_write(GifFileType *gif, const GifByteType *buf, int len)
{
	struct MemWriter *w = (struct MemWriter *)gif->UserData;
	if (w->len + (size_t)len > w->cap) {
		size_t newCap = (w->len + (size_t)len) * 2;
		uint8_t *newData = (uint8_t *)realloc(w->data, newCap);
		if (!newData) return 0;
		w->data = newData;
		w->cap = newCap;
	}
	memcpy(w->data + w->len, buf, (size_t)len);
	w->len += (size_t)len;
	return len;
}

// Decode-encode roundtrip using high-level API.
// Covers: DGifSlurp, GifMakeSavedImage, EGifSpew, GifUnionColorMap,
//         GifApplyTranslation, GifBitSize, GifFreeSavedImages,
//         GifDrawBox, GifDrawRectangle, GifDrawText8x8, GifDrawBoxedText8x8,
//         DGifExtensionToGCB, EGifGCBToExtension, EGifGCBToSavedExtension
static void roundtrip_high_level(const uint8_t *data, size_t size)
{
	int Error;
	struct MemReader reader = {data, size, 0};

	GifFileType *GifIn = DGifOpen(&reader, mem_read, &Error);
	if (!GifIn) return;

	if (DGifSlurp(GifIn) != GIF_OK) {
		DGifCloseFile(GifIn, &Error);
		return;
	}

	(void)GifBitSize(1);
	(void)GifBitSize(128);
	(void)GifBitSize(256);

	// Exercise GifUnionColorMap when both global and local maps exist
	if (GifIn->SColorMap && GifIn->ImageCount > 0 &&
	    GifIn->SavedImages[0].ImageDesc.ColorMap) {
		GifPixelType trans[256];
		ColorMapObject *merged = GifUnionColorMap(
			GifIn->SColorMap,
			GifIn->SavedImages[0].ImageDesc.ColorMap,
			trans);
		if (merged) {
			if (GifIn->SavedImages[0].RasterBits &&
			    GifIn->SavedImages[0].ImageDesc.Width > 0 &&
			    GifIn->SavedImages[0].ImageDesc.Height > 0) {
				GifApplyTranslation(&GifIn->SavedImages[0], trans);
			}
			GifFreeMapObject(merged);
		}
	}

	// GCB roundtrip: decode extension to GCB, serialize, write back
	for (int i = 0; i < GifIn->ImageCount && i < 8; i++) {
		GraphicsControlBlock gcb;
		if (DGifSavedExtensionToGCB(GifIn, i, &gcb) == GIF_OK) {
			GifByteType extBuf[4];
			EGifGCBToExtension(&gcb, extBuf);
			GraphicsControlBlock gcb2;
			DGifExtensionToGCB(4, extBuf, &gcb2);
			EGifGCBToSavedExtension(&gcb, GifIn, i);
		}
	}

	// Drawing functions on first image if dimensions are sufficient
	if (GifIn->ImageCount > 0) {
		SavedImage *img = &GifIn->SavedImages[0];
		int w = img->ImageDesc.Width;
		int h = img->ImageDesc.Height;
		if (img->RasterBits && w > 0 && h > 0) {
			int rw = w < 40 ? w : 40;
			int rh = h < 20 ? h : 20;
			GifDrawRectangle(img, 0, 0, rw, rh, 1);
			if (w >= 2 && h >= 2) {
				int bw = w < 30 ? w - 1 : 30;
				int bh = h < 15 ? h - 1 : 15;
				GifDrawBox(img, 0, 0, bw, bh, 2);
			}
			// GifDrawText8x8 needs x + 8*strlen <= width, y + 8 <= height
			if (w >= 32 && h >= 8) {
				GifDrawText8x8(img, 0, 0, "fuzz", 3);
			}
			// GifDrawBoxedText8x8: border + chars*8 + border
			// "AB\rCD" = 2 lines, 2 chars max: 1 + 16 + 1 = 18 wide/high
			if (w >= 18 && h >= 18) {
				GifDrawBoxedText8x8(img, 0, 0, "AB\rCD", 1, 0, 3);
			}
		}
	}

	// Re-encode via EGifSpew
	struct MemWriter writer = {NULL, 0, 0};
	writer.data = (uint8_t *)malloc(4096);
	if (!writer.data) {
		DGifCloseFile(GifIn, &Error);
		return;
	}
	writer.cap = 4096;

	GifFileType *GifOut = EGifOpen(&writer, mem_write, &Error);
	if (GifOut) {
		GifOut->SWidth = GifIn->SWidth;
		GifOut->SHeight = GifIn->SHeight;
		GifOut->SColorResolution = GifIn->SColorResolution;
		GifOut->SBackGroundColor = GifIn->SBackGroundColor;
		if (GifIn->SColorMap) {
			GifOut->SColorMap = GifMakeMapObject(
				GifIn->SColorMap->ColorCount,
				GifIn->SColorMap->Colors);
		}
		for (int i = 0; i < GifIn->ImageCount && i < 16; i++) {
			GifMakeSavedImage(GifOut, &GifIn->SavedImages[i]);
		}
		// EGifSpew writes everything and calls EGifCloseFile internally
		EGifSpew(GifOut, &Error);
	}

	free(writer.data);
	DGifCloseFile(GifIn, &Error);
}

// Low-level record-by-record decode.
// Covers: DGifGetRecordType, DGifGetImageDesc, DGifGetLine,
//         DGifGetPixel, DGifGetExtension, DGifGetExtensionNext,
//         DGifGetCode, DGifGetCodeNext, DGifGetGifVersion
static void lowlevel_decode(const uint8_t *data, size_t size)
{
	int Error;
	struct MemReader reader = {data, size, 0};

	GifFileType *GifFile = DGifOpen(&reader, mem_read, &Error);
	if (!GifFile) return;

	GifRecordType RecordType;
	int imageIndex = 0;
	bool done = false;

	while (!done) {
		if (DGifGetRecordType(GifFile, &RecordType) == GIF_ERROR)
			break;

		switch (RecordType) {
		case IMAGE_DESC_RECORD_TYPE: {
			if (DGifGetImageDesc(GifFile) == GIF_ERROR) {
				done = true;
				break;
			}
			int w = GifFile->Image.Width;
			int h = GifFile->Image.Height;
			if (w <= 0 || h <= 0 || w > 4096 || h > 4096) {
				done = true;
				break;
			}

			if (imageIndex % 3 == 0) {
				// Line-by-line reading
				GifPixelType *line = (GifPixelType *)malloc(w);
				if (!line) { done = true; break; }
				for (int i = 0; i < h && i < 256; i++) {
					if (DGifGetLine(GifFile, line, w) == GIF_ERROR)
						break;
				}
				free(line);
			} else if (imageIndex % 3 == 1) {
				// Pixel-by-pixel for first row, then line for rest
				int pixels_read = 0;
				for (int j = 0; j < w && j < 64; j++) {
					if (DGifGetPixel(GifFile, 0) == GIF_ERROR)
						break;
					pixels_read++;
				}
				// Drain remaining pixels
				int remaining_first_row = w - pixels_read;
				GifPixelType *buf = (GifPixelType *)malloc(w);
				if (buf) {
					if (remaining_first_row > 0) {
						DGifGetLine(GifFile, buf, remaining_first_row);
					}
					for (int row = 1; row < h && row < 256; row++) {
						if (DGifGetLine(GifFile, buf, w) == GIF_ERROR)
							break;
					}
					free(buf);
				}
			} else {
				// Raw LZW code blocks
				int CodeSize;
				GifByteType *CodeBlock;
				if (DGifGetCode(GifFile, &CodeSize, &CodeBlock) == GIF_OK) {
					while (CodeBlock != NULL) {
						if (DGifGetCodeNext(GifFile, &CodeBlock) == GIF_ERROR)
							break;
					}
				}
			}
			imageIndex++;
			if (imageIndex > 16) done = true;
			break;
		}
		case EXTENSION_RECORD_TYPE: {
			int ExtCode;
			GifByteType *ExtData;
			if (DGifGetExtension(GifFile, &ExtCode, &ExtData) == GIF_ERROR) {
				done = true;
				break;
			}
			while (ExtData != NULL) {
				if (DGifGetExtensionNext(GifFile, &ExtData) == GIF_ERROR) {
					done = true;
					break;
				}
			}
			break;
		}
		case TERMINATE_RECORD_TYPE:
			done = true;
			break;
		default:
			done = true;
			break;
		}
	}

	(void)DGifGetGifVersion(GifFile);
	DGifCloseFile(GifFile, &Error);
}

// Encode with extensions, comments, and pixel-by-pixel writing.
// Covers: EGifPutComment, EGifPutExtensionLeader/Block/Trailer,
//         EGifPutExtension, EGifPutPixel, EGifGetGifVersion,
//         EGifSetGifVersion(true)
static void enhanced_encode(const uint8_t *data, size_t size)
{
	if (size < 10) return;

	int Error;
	struct MemWriter writer = {NULL, 0, 0};
	writer.data = (uint8_t *)malloc(4096);
	if (!writer.data) return;
	writer.cap = 4096;

	GifFileType *GifFile = EGifOpen(&writer, mem_write, &Error);
	if (!GifFile) {
		free(writer.data);
		return;
	}

	EGifSetGifVersion(GifFile, true);
	(void)EGifGetGifVersion(GifFile);

	int w = (data[0] % 32) + 8;
	int h = (data[1] % 32) + 8;
	int colorBits = (data[2] % 3) + 2;
	int colorCount = 1 << colorBits;

	ColorMapObject *cmap = GifMakeMapObject(colorCount, NULL);
	if (!cmap) {
		EGifCloseFile(GifFile, &Error);
		free(writer.data);
		return;
	}
	for (int i = 0; i < colorCount && (size_t)(3 + i * 3 + 2) < size; i++) {
		cmap->Colors[i].Red = data[3 + i * 3];
		cmap->Colors[i].Green = data[3 + i * 3 + 1];
		cmap->Colors[i].Blue = data[3 + i * 3 + 2];
	}

	if (EGifPutScreenDesc(GifFile, w, h, colorCount, 0, cmap) == GIF_ERROR) {
		GifFreeMapObject(cmap);
		EGifCloseFile(GifFile, &Error);
		free(writer.data);
		return;
	}

	EGifPutComment(GifFile, "fuzz test");

	// Multi-block extension via leader/block/trailer
	EGifPutExtensionLeader(GifFile, APPLICATION_EXT_FUNC_CODE);
	EGifPutExtensionBlock(GifFile, 11, "NETSCAPE2.0");
	unsigned char loopData[3] = {1, 0, 0};
	EGifPutExtensionBlock(GifFile, 3, loopData);
	EGifPutExtensionTrailer(GifFile);

	// Graphics control extension via EGifPutExtension
	GraphicsControlBlock gcb;
	gcb.DisposalMode = DISPOSE_DO_NOT;
	gcb.UserInputFlag = false;
	gcb.DelayTime = 10;
	gcb.TransparentColor = NO_TRANSPARENT_COLOR;
	GifByteType ext[4];
	size_t extLen = EGifGCBToExtension(&gcb, ext);
	EGifPutExtension(GifFile, GRAPHICS_EXT_FUNC_CODE, (int)extLen, ext);

	// Write image data
	GifPixelType *line = (GifPixelType *)calloc(w, 1);
	if (!line) {
		GifFreeMapObject(cmap);
		EGifCloseFile(GifFile, &Error);
		free(writer.data);
		return;
	}

	if (EGifPutImageDesc(GifFile, 0, 0, w, h, false, NULL) == GIF_OK) {
		// First row: pixel-by-pixel
		for (int x = 0; x < w; x++) {
			GifPixelType pixel = ((size_t)(10 + x) < size) ?
				data[10 + x] % colorCount : 0;
			if (EGifPutPixel(GifFile, pixel) == GIF_ERROR)
				break;
		}
		// Remaining rows: line-by-line
		for (int y = 1; y < h; y++) {
			for (int x = 0; x < w; x++) {
				size_t idx = (size_t)(10 + y * w + x);
				line[x] = (idx < size) ? data[idx] % colorCount : 0;
			}
			if (EGifPutLine(GifFile, line, w) == GIF_ERROR)
				break;
		}
	}

	free(line);
	GifFreeMapObject(cmap);
	EGifCloseFile(GifFile, &Error);
	free(writer.data);
}

static void exercise_error_strings(void)
{
	// D_GIF_ERR: 101-113, E_GIF_ERR: 201-210
	for (int i = 101; i <= 113; i++)
		(void)GifErrorString(i);
	for (int i = 201; i <= 210; i++)
		(void)GifErrorString(i);
	(void)GifErrorString(0);
	(void)GifErrorString(999);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
	if (Size < 6) return 0;

	roundtrip_high_level(Data, Size);
	lowlevel_decode(Data, Size);
	enhanced_encode(Data, Size);
	exercise_error_strings();

	return 0;
}
