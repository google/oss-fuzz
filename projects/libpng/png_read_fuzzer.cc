// OSS-Fuzz fuzzing harness for libpng read paths.
// Covers:
//   1. png_read_png()  - high-level one-shot read
//   2. png_read_image() - row-by-row read after png_read_info()
//   3. Progressive read via png_process_data()
//
// Build with: clang++ -g -fsanitize=address,undefined -lpng -lz png_read_fuzzer.cc -o png_read_fuzzer

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <setjmp.h>

#include "png.h"

// ---------------------------------------------------------------------------
// Memory-backed I/O helpers
// ---------------------------------------------------------------------------

struct MemReader {
  const uint8_t *data;
  size_t         size;
  size_t         pos;
};

static void mem_read_fn(png_structp png_ptr, png_bytep out, png_size_t len) {
  MemReader *r = reinterpret_cast<MemReader *>(png_get_io_ptr(png_ptr));
  if (r->pos + len > r->size) {
    // Signal error – libpng will longjmp out.
    png_error(png_ptr, "read beyond end of buffer");
    return;
  }
  memcpy(out, r->data + r->pos, len);
  r->pos += len;
}

// ---------------------------------------------------------------------------
// Path 1 – png_read_png() (high-level, all transforms)
// ---------------------------------------------------------------------------

static void fuzz_read_png(const uint8_t *data, size_t size) {
  MemReader reader = {data, size, 0};

  png_structp png_ptr = png_create_read_struct(
      PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
  if (!png_ptr) return;

  png_infop info_ptr = png_create_info_struct(png_ptr);
  if (!info_ptr) {
    png_destroy_read_struct(&png_ptr, nullptr, nullptr);
    return;
  }

  if (setjmp(png_jmpbuf(png_ptr))) {
    png_destroy_read_struct(&png_ptr, &info_ptr, nullptr);
    return;
  }

  png_set_read_fn(png_ptr, &reader, mem_read_fn);

  // Exercise a wide set of transforms to maximise code coverage.
  int transforms = PNG_TRANSFORM_STRIP_16   |
                   PNG_TRANSFORM_PACKING    |
                   PNG_TRANSFORM_EXPAND     |
                   PNG_TRANSFORM_BGR        |
                   PNG_TRANSFORM_GRAY_TO_RGB;

  png_read_png(png_ptr, info_ptr, transforms, nullptr);

  png_destroy_read_struct(&png_ptr, &info_ptr, nullptr);
}

// ---------------------------------------------------------------------------
// Path 2 – png_read_info() + png_read_image() + png_read_end()
// ---------------------------------------------------------------------------

static void fuzz_read_image(const uint8_t *data, size_t size) {
  MemReader reader = {data, size, 0};

  png_structp png_ptr = png_create_read_struct(
      PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
  if (!png_ptr) return;

  png_infop info_ptr  = png_create_info_struct(png_ptr);
  png_infop end_info  = png_create_info_struct(png_ptr);
  if (!info_ptr || !end_info) {
    png_destroy_read_struct(&png_ptr, &info_ptr, &end_info);
    return;
  }

  if (setjmp(png_jmpbuf(png_ptr))) {
    png_destroy_read_struct(&png_ptr, &info_ptr, &end_info);
    return;
  }

  png_set_read_fn(png_ptr, &reader, mem_read_fn);

  png_read_info(png_ptr, info_ptr);

  png_uint_32 width  = png_get_image_width(png_ptr, info_ptr);
  png_uint_32 height = png_get_image_height(png_ptr, info_ptr);

  // Guard against absurdly large dimensions to keep run-time sane.
  if (width == 0 || height == 0 || width > 4096 || height > 4096) {
    png_destroy_read_struct(&png_ptr, &info_ptr, &end_info);
    return;
  }

  size_t row_bytes = png_get_rowbytes(png_ptr, info_ptr);
  if (row_bytes == 0 || row_bytes > 4096 * 8) {
    png_destroy_read_struct(&png_ptr, &info_ptr, &end_info);
    return;
  }

  // Allocate row pointers.
  png_bytepp rows = reinterpret_cast<png_bytepp>(
      malloc(height * sizeof(png_bytep)));
  if (!rows) {
    png_destroy_read_struct(&png_ptr, &info_ptr, &end_info);
    return;
  }
  for (png_uint_32 i = 0; i < height; ++i) {
    rows[i] = reinterpret_cast<png_bytep>(malloc(row_bytes));
    if (!rows[i]) {
      // Free what we've allocated so far, then bail.
      for (png_uint_32 j = 0; j < i; ++j) free(rows[j]);
      free(rows);
      png_destroy_read_struct(&png_ptr, &info_ptr, &end_info);
      return;
    }
  }

  png_read_image(png_ptr, rows);
  png_read_end(png_ptr, end_info);

  for (png_uint_32 i = 0; i < height; ++i) free(rows[i]);
  free(rows);
  png_destroy_read_struct(&png_ptr, &info_ptr, &end_info);
}

// ---------------------------------------------------------------------------
// Path 3 – Progressive read via png_process_data()
// ---------------------------------------------------------------------------

// We don't do anything with the decoded rows; we just exercise the path.
static void info_callback(png_structp /*png_ptr*/, png_infop /*info_ptr*/) {}
static void row_callback(png_structp /*png_ptr*/, png_bytep /*row*/,
                         png_uint_32 /*row_num*/, int /*pass*/) {}
static void end_callback(png_structp /*png_ptr*/, png_infop /*info_ptr*/) {}

static void fuzz_progressive(const uint8_t *data, size_t size) {
  png_structp png_ptr = png_create_read_struct(
      PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
  if (!png_ptr) return;

  png_infop info_ptr = png_create_info_struct(png_ptr);
  if (!info_ptr) {
    png_destroy_read_struct(&png_ptr, nullptr, nullptr);
    return;
  }

  if (setjmp(png_jmpbuf(png_ptr))) {
    png_destroy_read_struct(&png_ptr, &info_ptr, nullptr);
    return;
  }

  png_set_progressive_read_fn(png_ptr, nullptr,
                               info_callback, row_callback, end_callback);

  // Feed data in variable-sized chunks (powers of 2) to stress the
  // progressive decoder's internal state machine.
  const size_t chunk_sizes[] = {1, 4, 16, 64, 256, 1024};
  const size_t n_chunks = sizeof(chunk_sizes) / sizeof(chunk_sizes[0]);

  size_t pos = 0;
  size_t chunk_idx = 0;
  while (pos < size) {
    size_t chunk = chunk_sizes[chunk_idx % n_chunks];
    if (chunk > size - pos) chunk = size - pos;
    png_process_data(png_ptr, info_ptr,
                     const_cast<png_bytep>(data + pos), chunk);
    pos += chunk;
    ++chunk_idx;
  }

  png_destroy_read_struct(&png_ptr, &info_ptr, nullptr);
}

// ---------------------------------------------------------------------------
// Fuzzer entry point
// ---------------------------------------------------------------------------

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Need at least a byte to dispatch and a minimal header (8 bytes).
  if (size < 9) return 0;

  // Use the first byte as a path selector so all three paths get exercised.
  uint8_t selector = data[0] % 3;
  const uint8_t *payload = data + 1;
  size_t         payload_size = size - 1;

  switch (selector) {
    case 0: fuzz_read_png(payload, payload_size);   break;
    case 1: fuzz_read_image(payload, payload_size); break;
    case 2: fuzz_progressive(payload, payload_size); break;
  }

  return 0;
}
