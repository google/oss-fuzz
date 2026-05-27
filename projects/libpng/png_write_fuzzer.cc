// OSS-Fuzz fuzzing harness for libpng write path.
// Strategy: treat raw fuzz bytes as pixel data, write them as a PNG into an
// in-memory buffer via png_write_png(), then read that buffer back with
// png_read_png() to exercise the full encode→decode roundtrip.
//
// Build with: clang++ -g -fsanitize=address,undefined -lpng -lz png_write_fuzzer.cc -o png_write_fuzzer

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <setjmp.h>
#include <vector>
#include <algorithm>

#include "png.h"

// ---------------------------------------------------------------------------
// Memory-backed write I/O
// ---------------------------------------------------------------------------

struct MemWriter {
  std::vector<uint8_t> buf;
};

static void mem_write_fn(png_structp png_ptr, png_bytep data, png_size_t len) {
  MemWriter *w = reinterpret_cast<MemWriter *>(png_get_io_ptr(png_ptr));
  w->buf.insert(w->buf.end(), data, data + len);
}

static void mem_flush_fn(png_structp /*png_ptr*/) {
  // Nothing to flush for in-memory I/O.
}

// ---------------------------------------------------------------------------
// Memory-backed read I/O (for the decode side)
// ---------------------------------------------------------------------------

struct MemReader {
  const uint8_t *data;
  size_t         size;
  size_t         pos;
};

static void mem_read_fn(png_structp png_ptr, png_bytep out, png_size_t len) {
  MemReader *r = reinterpret_cast<MemReader *>(png_get_io_ptr(png_ptr));
  if (r->pos + len > r->size) {
    png_error(png_ptr, "read beyond end of buffer");
    return;
  }
  memcpy(out, r->data + r->pos, len);
  r->pos += len;
}

// ---------------------------------------------------------------------------
// Write path: encode arbitrary bytes as a grayscale PNG
// ---------------------------------------------------------------------------

static bool write_png(const uint8_t *data, size_t size,
                      MemWriter &writer,
                      png_uint_32 &out_width, png_uint_32 &out_height) {
  if (size == 0) return false;

  // Treat the input as rows of 8-bit grayscale pixels.
  // Width is fixed at up to 64; height is derived from size.
  const png_uint_32 width  = std::min<png_uint_32>(64, (png_uint_32)size);
  const png_uint_32 height = (png_uint_32)((size + width - 1) / width);

  // Guard against degenerate dimensions.
  if (width == 0 || height == 0 || height > 4096) return false;

  out_width  = width;
  out_height = height;

  png_structp png_ptr = png_create_write_struct(
      PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
  if (!png_ptr) return false;

  png_infop info_ptr = png_create_info_struct(png_ptr);
  if (!info_ptr) {
    png_destroy_write_struct(&png_ptr, nullptr);
    return false;
  }

  if (setjmp(png_jmpbuf(png_ptr))) {
    png_destroy_write_struct(&png_ptr, &info_ptr);
    return false;
  }

  png_set_write_fn(png_ptr, &writer, mem_write_fn, mem_flush_fn);

  // Use compression level from the first byte so the fuzzer can vary it.
  int clevel = (int)(data[0] % 10);
  png_set_compression_level(png_ptr, clevel);

  png_set_IHDR(png_ptr, info_ptr,
               width, height,
               8,                      // bit depth
               PNG_COLOR_TYPE_GRAY,    // color type
               PNG_INTERLACE_NONE,
               PNG_COMPRESSION_TYPE_DEFAULT,
               PNG_FILTER_TYPE_DEFAULT);

  // Build row pointer array, padding the last row with zeros if needed.
  size_t row_bytes = (size_t)width;
  std::vector<uint8_t> padded(height * row_bytes, 0);
  memcpy(padded.data(), data, std::min(size, padded.size()));

  std::vector<png_bytep> rows(height);
  for (png_uint_32 i = 0; i < height; ++i)
    rows[i] = padded.data() + i * row_bytes;

  png_set_rows(png_ptr, info_ptr, rows.data());
  png_write_png(png_ptr, info_ptr, PNG_TRANSFORM_IDENTITY, nullptr);

  png_destroy_write_struct(&png_ptr, &info_ptr);
  return true;
}

// ---------------------------------------------------------------------------
// Read path: decode the PNG we just wrote back into memory
// ---------------------------------------------------------------------------

static void read_back_png(const MemWriter &writer) {
  if (writer.buf.empty()) return;

  MemReader reader = {writer.buf.data(), writer.buf.size(), 0};

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
  png_read_png(png_ptr, info_ptr, PNG_TRANSFORM_IDENTITY, nullptr);
  png_destroy_read_struct(&png_ptr, &info_ptr, nullptr);
}

// ---------------------------------------------------------------------------
// Auxiliary path: exercise png_write_row() individually
// ---------------------------------------------------------------------------

static void fuzz_write_row(const uint8_t *data, size_t size) {
  if (size < 2) return;

  const png_uint_32 width  = std::min<png_uint_32>(64, (png_uint_32)size);
  const png_uint_32 height = (png_uint_32)((size + width - 1) / width);
  if (height == 0 || height > 4096) return;

  MemWriter writer;

  png_structp png_ptr = png_create_write_struct(
      PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
  if (!png_ptr) return;

  png_infop info_ptr = png_create_info_struct(png_ptr);
  if (!info_ptr) {
    png_destroy_write_struct(&png_ptr, nullptr);
    return;
  }

  if (setjmp(png_jmpbuf(png_ptr))) {
    png_destroy_write_struct(&png_ptr, &info_ptr);
    return;
  }

  png_set_write_fn(png_ptr, &writer, mem_write_fn, mem_flush_fn);
  png_set_IHDR(png_ptr, info_ptr,
               width, height, 8,
               PNG_COLOR_TYPE_GRAY,
               PNG_INTERLACE_NONE,
               PNG_COMPRESSION_TYPE_DEFAULT,
               PNG_FILTER_TYPE_DEFAULT);
  png_write_info(png_ptr, info_ptr);

  size_t row_bytes = (size_t)width;
  std::vector<uint8_t> row_buf(row_bytes, 0);
  for (png_uint_32 i = 0; i < height; ++i) {
    size_t src_offset = (size_t)i * row_bytes;
    if (src_offset < size) {
      size_t avail = std::min(row_bytes, size - src_offset);
      memcpy(row_buf.data(), data + src_offset, avail);
    } else {
      memset(row_buf.data(), 0, row_bytes);
    }
    png_write_row(png_ptr, row_buf.data());
  }

  png_write_end(png_ptr, info_ptr);
  png_destroy_write_struct(&png_ptr, &info_ptr);
}

// ---------------------------------------------------------------------------
// Fuzzer entry point
// ---------------------------------------------------------------------------

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2) return 0;

  // Use the first byte to select between write-path variants.
  uint8_t selector = data[0] % 2;
  const uint8_t *payload = data + 1;
  size_t         payload_size = size - 1;

  switch (selector) {
    case 0: {
      // Full roundtrip: write → read-back.
      MemWriter writer;
      png_uint_32 w = 0, h = 0;
      if (write_png(payload, payload_size, writer, w, h)) {
        read_back_png(writer);
      }
      break;
    }
    case 1: {
      // Row-by-row write path.
      fuzz_write_row(payload, payload_size);
      break;
    }
  }

  return 0;
}
