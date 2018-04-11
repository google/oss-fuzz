#include <cstdint>
#include <sstream>
#include <tiffio.h>
#include <tiffio.hxx>


/* stolen from tiffiop.h, which is a private header so we can't just include it */
/* safe multiply returns either the multiplied value or 0 if it overflowed */
#define __TIFFSafeMultiply(t,v,m) ((((t)(m) != (t)0) && (((t)(((v)*(m))/(m))) == (t)(v))) ? (t)((v)*(m)) : (t)0)

const tmsize_t MAX_SIZE = 500000000;

extern "C" void handle_error(const char *unused, const char *unused2, va_list unused3) {
    return;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  TIFFSetErrorHandler(handle_error);
  TIFFSetWarningHandler(handle_error);
  std::istringstream s(std::string(Data,Data+Size));
  TIFF* tif = TIFFStreamOpen("MemTIFF", &s);
  if (!tif) {
      return 0;
  }
  uint32 w, h;
  size_t npixels;
  uint32* raster;

  TIFFGetField(tif, TIFFTAG_IMAGEWIDTH, &w);
  TIFFGetField(tif, TIFFTAG_IMAGELENGTH, &h);
  /* don't continue if image has negative size or the file size is ludicrous */
  if (TIFFTileSize(tif) > MAX_SIZE || w <=0 || h <= 0) {
      TIFFClose(tif);
      return 0;
  }
  tmsize_t bufsize = __TIFFSafeMultiply(tmsize_t, TIFFTileSize(tif), 4);
  /* don't continue if the buffer size greater than the max allowed by the fuzzer */
  if (bufsize > MAX_SIZE || bufsize == 0) {
      TIFFClose(tif);
      return 0;
  }
  /* another hack to work around an OOM in tif_fax3.c */
  uint32 tilewidth = 0;
  uint32 imagewidth = 0;
  TIFFGetField(tif, TIFFTAG_TILEWIDTH, &tilewidth);
  TIFFGetField(tif, TIFFTAG_IMAGEWIDTH, &imagewidth);
  tilewidth = __TIFFSafeMultiply(uint32, tilewidth, 2);
  imagewidth = __TIFFSafeMultiply(uint32, imagewidth, 2);
  if (tilewidth * 2 > MAX_SIZE || imagewidth * 2 > MAX_SIZE || tilewidth == 0 || imagewidth == 0) {
      TIFFClose(tif);
      return 0;
  }
  npixels = w * h;
  uint32 size = __TIFFSafeMultiply(uint32, w, h);
  if (size > MAX_SIZE || size == 0) {
      TIFFClose(tif);
      return 0;
  }
  raster = (uint32*) _TIFFmalloc(npixels * sizeof (uint32));
  if (raster != NULL) {
      TIFFReadRGBAImage(tif, w, h, raster, 0);
      _TIFFfree(raster);
  }
  TIFFClose(tif);

  return 0;
}
