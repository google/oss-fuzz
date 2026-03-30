#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include "zlib.h"

#define CHECK_ERR(err, msg) { \
    if (err != Z_OK) { \
        fprintf(stderr, "%s error: %d\n", msg, err); \
        return 0; \
    } \
}

static const uint8_t *data;
static size_t dataLen;
static alloc_func zalloc = NULL;
static free_func zfree = NULL;

/* ===========================================================================
 * Test deflate() with large buffers and dynamic change of compression level
 */
int test_large_deflate(unsigned char *compr, size_t comprLen,
                        unsigned char *uncompr, size_t uncomprLen,
                        unsigned int *diff_out) {
  z_stream c_stream; /* compression stream */
  int err;
  int ret = 0;

  c_stream.zalloc = zalloc;
  c_stream.zfree = zfree;
  c_stream.opaque = (void *)0;

  err = deflateInit(&c_stream, Z_BEST_COMPRESSION);
  CHECK_ERR(err, "deflateInit");

  c_stream.next_out = compr;
  c_stream.avail_out = (unsigned int)comprLen;

  /* Use the actual fuzz data, not zeros */
  c_stream.next_in = (Bytef *)data;
  c_stream.avail_in = (unsigned int)dataLen;
  err = deflate(&c_stream, Z_NO_FLUSH);
  CHECK_ERR(err, "deflate large 1");
  if (c_stream.avail_in != 0) {
    fprintf(stderr, "deflate not greedy\n");
    goto cleanup;
  }

  /* Feed in already compressed data and switch to no compression: */
  deflateParams(&c_stream, Z_NO_COMPRESSION, Z_DEFAULT_STRATEGY);
  c_stream.next_in = compr;
  *diff_out = (unsigned int)(c_stream.next_out - compr);
  c_stream.avail_in = *diff_out;
  err = deflate(&c_stream, Z_NO_FLUSH);
  CHECK_ERR(err, "deflate large 2");

  /* Switch back to compressing mode: */
  deflateParams(&c_stream, Z_BEST_COMPRESSION, Z_FILTERED);
  c_stream.next_in = (Bytef *)data;
  c_stream.avail_in = (unsigned int)dataLen;
  err = deflate(&c_stream, Z_NO_FLUSH);
  CHECK_ERR(err, "deflate large 3");

  err = deflate(&c_stream, Z_FINISH);
  if (err != Z_STREAM_END) {
    fprintf(stderr, "deflate large should report Z_STREAM_END\n");
    goto cleanup;
  }
  ret = 1;

cleanup:
  err = deflateEnd(&c_stream);
  if (err != Z_OK) {
    fprintf(stderr, "deflateEnd error: %d\n", err);
    ret = 0;
  }
  return ret;
}

/* ===========================================================================
 * Test inflate() with large buffers
 */
int test_large_inflate(unsigned char *compr, size_t comprLen,
                        unsigned char *uncompr, size_t uncomprLen,
                        unsigned int diff) {
  int err;
  z_stream d_stream; /* decompression stream */
  int ret = 0;

  d_stream.zalloc = zalloc;
  d_stream.zfree = zfree;
  d_stream.opaque = (void *)0;

  d_stream.next_in = compr;
  d_stream.avail_in = (unsigned int)comprLen;

  err = inflateInit(&d_stream);
  CHECK_ERR(err, "inflateInit");

  for (;;) {
    d_stream.next_out = uncompr; /* discard the output */
    d_stream.avail_out = (unsigned int)uncomprLen;
    err = inflate(&d_stream, Z_NO_FLUSH);
    if (err == Z_STREAM_END)
      break;
    CHECK_ERR(err, "large inflate");
  }

  err = inflateEnd(&d_stream);
  CHECK_ERR(err, "inflateEnd");

  if (d_stream.total_out != 2 * dataLen + diff) {
    fprintf(stderr, "bad large inflate: %zu\n", d_stream.total_out);
    goto cleanup;
  }
  ret = 1;

cleanup:
  err = inflateEnd(&d_stream);
  if (err != Z_OK) {
    fprintf(stderr, "inflateEnd error: %d\n", err);
    ret = 0;
  }
  return ret;
}

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t size) {
  size_t comprLen = 100 + 3 * size;
  size_t uncomprLen = size;
  uint8_t *compr, *uncompr;
  unsigned int diff = 0;
  int ret_deflate, ret_inflate;

  /* Discard inputs larger than 512Kb. */
  static size_t kMaxSize = 512 * 1024;

  if (size < 1 || size > kMaxSize)
    return 0;

  data = d;
  dataLen = size;
  compr = (uint8_t *)calloc(1, comprLen);
  uncompr = (uint8_t *)calloc(1, uncomprLen);

  /* Copy fuzz data to uncompr buffer for inflation output */
  memcpy(uncompr, data, dataLen);

  ret_deflate = test_large_deflate(compr, comprLen, uncompr, uncomprLen, &diff);
  if (ret_deflate) {
    ret_inflate = test_large_inflate(compr, comprLen, uncompr, uncomprLen, diff);
  }

  free(compr);
  free(uncompr);

  /* This function must return 0. */
  return 0;
}