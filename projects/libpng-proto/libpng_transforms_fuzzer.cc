#include <algorithm>
#include <cassert>
#include <cstring>
#include <string>
#include <vector>

#include "png.h"

namespace {

struct PngReader {
  png_structp png_ptr = nullptr;
  png_infop info_ptr = nullptr;
  png_infop end_info = nullptr;
};

struct PngArrayStream {
  const uint8_t *data;
  size_t size;
  size_t pos;
};

void PngArrayStreamCallback(png_structp png_ptr, png_bytep data,
                            png_size_t size) {
  PngArrayStream *stream =
      static_cast<PngArrayStream *>(png_get_io_ptr(png_ptr));
  if (stream->pos + size > stream->size) {
    memset(data, 0, size);
    stream->pos = size;
  } else {
    memcpy(data, &stream->data[stream->pos], size);
    stream->pos += size;
  }
}

static bool PngVerboseWarnings = getenv("PNG_VERBOSE_WARNINGS") != nullptr;

void PngErrorHandler(png_structp png_ptr, png_const_charp error_message) {
  if (PngVerboseWarnings) fprintf(stderr, "%s\n", error_message);
  longjmp(png_jmpbuf(png_ptr), 1);
}

void PngWarningHandler(png_structp png_ptr, png_const_charp warning_message) {
  if (PngVerboseWarnings) fprintf(stderr, "%s\n", warning_message);
  longjmp(png_jmpbuf(png_ptr), 1);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const size_t kPngSignatureSize = 8;
  const size_t kIHDRSize = 4 + 4 + 13 + 4;
  const size_t kMaxImageSize = 1 << 20;
  const size_t kMaxHeight = 1 << 10;

  auto Read32 = [&](const uint8_t *p) {
    uint32_t res;
    assert(p >= data);
    assert(p + sizeof(res) < data + size);
    memcpy(&res, p, sizeof(res));
    return res;
  };

  if (size < kPngSignatureSize + kIHDRSize) return 0;
  if (png_sig_cmp(data, 0, kPngSignatureSize)) return 0;
  uint32_t width = __builtin_bswap32(Read32(data + kPngSignatureSize + 8));
  uint32_t height = __builtin_bswap32(Read32(data + kPngSignatureSize + 12));
  // Reject too large images because they will OOM.
  // Also reject images with a too large height, because large height
  // will cause too many mallocs.
  // These two heuristics are far from optimal and may cause us to lose some
  // coverage. But w/o them fuzzing is way too slow.
  if ((uint64_t)width * height > kMaxImageSize) return 0;
  if (height > kMaxHeight) return 0;

  // Find the fUZz chunk and it's contents.
  const size_t fUZz_chunk_size = 16;
  const uint8_t fUZz_signature[8] = {0,   0,   0,   fUZz_chunk_size,
                                     'f', 'U', 'Z', 'z'};
  const uint8_t *fUZz_beg =
      std::search(data, data + size, fUZz_signature,
                  fUZz_signature + sizeof(fUZz_signature));
  if (fUZz_beg + sizeof(fUZz_signature) + fUZz_chunk_size < data + size)
    fUZz_beg += sizeof(fUZz_signature);
  else
    fUZz_beg = nullptr;

  PngReader reader;
  reader.png_ptr =
      png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
  assert(reader.png_ptr);
  reader.info_ptr = png_create_info_struct(reader.png_ptr);
  assert(reader.info_ptr);
  reader.end_info = png_create_info_struct(reader.png_ptr);
  assert(reader.end_info);

  png_set_error_fn(reader.png_ptr, png_get_error_ptr(reader.png_ptr),
                   PngErrorHandler, PngWarningHandler);

  PngArrayStream stream{data, size, 0};

  if (setjmp(png_jmpbuf(reader.png_ptr)) == 0) {
    png_set_read_fn(reader.png_ptr, &stream, PngArrayStreamCallback);

    // Take transforms from the fUZz chunk. By default, enable all.
    int transforms = fUZz_beg ? Read32(fUZz_beg) : ~0;
    png_read_png(reader.png_ptr, reader.info_ptr, transforms, nullptr);
  }
  png_destroy_read_struct(&reader.png_ptr, &reader.info_ptr, &reader.end_info);

  // Run the same image through another libpng API.
  // There is probably some redundancy here (I don't know what I am doing!)
  png_image image;
  memset(&image, 0, sizeof(image));
  image.version = PNG_IMAGE_VERSION;
  if (png_image_begin_read_from_memory(&image, data, size)) {
    const size_t kMaxBufferSize = 64 << 20;
    image.format = fUZz_beg ? Read32(fUZz_beg + 4) : PNG_FORMAT_RGBA;
    size_t image_size = PNG_IMAGE_SIZE(image);
    if (image_size <= kMaxBufferSize) {
      png_bytep buffer = new png_byte[image_size];
      const size_t kColorMapSize = 256 * 4;
      // Do we need to take color & colormap from the fuzzed input?
      png_color color = {1, 2, 3};
      png_uint_16 colormap[256*4] = {0};
      for (size_t i = 0; i < kColorMapSize; i++)
        colormap[i] = i;
      png_image_finish_read(&image, &color, buffer, 0, colormap);
      delete[] buffer;
    }
  }
  png_image_free(&image);
  return 0;
}

extern "C" const char *__asan_default_options() {	
  // TODO: remove this once	
  // https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=12716	
  // is fixed.	
  return "detect_leaks=0";	
}
