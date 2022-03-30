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
        exit(1); \
    } \
}

static const uint8_t *data;
static size_t dataLen;
static alloc_func zalloc = NULL;
static free_func zfree = NULL;

/* ===========================================================================
 * Test deflate() with full flush
 */
void test_flush(unsigned char *compr, z_size_t *comprLen) {
  z_stream c_stream; /* compression stream */
  int err;
  unsigned int len = dataLen;

  c_stream.zalloc = zalloc;
  c_stream.zfree = zfree;
  c_stream.opaque = (void *)0;

  err = deflateInit(&c_stream, Z_DEFAULT_COMPRESSION);
  CHECK_ERR(err, "deflateInit");

  c_stream.next_in = (Bytef *)data;
  c_stream.next_out = compr;
  c_stream.avail_in = 3;
  c_stream.avail_out = (unsigned int)*comprLen;
  err = deflate(&c_stream, Z_FULL_FLUSH);
  CHECK_ERR(err, "deflate flush 1");

  compr[3]++; /* force an error in first compressed block */
  c_stream.avail_in = len - 3;

  err = deflate(&c_stream, Z_FINISH);
  if (err != Z_STREAM_END) {
    CHECK_ERR(err, "deflate flush 2");
  }
  err = deflateEnd(&c_stream);
  CHECK_ERR(err, "deflateEnd");

  *comprLen = (z_size_t)c_stream.total_out;
}

/* ===========================================================================
 * Test inflateSync()
 */
void test_sync(unsigned char *compr, size_t comprLen, unsigned char *uncompr,
               size_t uncomprLen) {
  int err;
  z_stream d_stream; /* decompression stream */

  d_stream.zalloc = zalloc;
  d_stream.zfree = zfree;
  d_stream.opaque = (void *)0;

  d_stream.next_in = compr;
  d_stream.avail_in = 2; /* just read the zlib header */

  err = inflateInit(&d_stream);
  CHECK_ERR(err, "inflateInit");

  d_stream.next_out = uncompr;
  d_stream.avail_out = (unsigned int)uncomprLen;

  err = inflate(&d_stream, Z_NO_FLUSH);
  CHECK_ERR(err, "inflate");

  d_stream.avail_in = (unsigned int)comprLen - 2; /* read all compressed data */
  err = inflateSync(&d_stream); /* but skip the damaged part */
  CHECK_ERR(err, "inflateSync");

  err = inflate(&d_stream, Z_FINISH);
  if (err != Z_DATA_ERROR) {
    fprintf(stderr, "inflate should report DATA_ERROR\n");
    /* Because of incorrect adler32 */
    exit(1);
  }
  err = inflateEnd(&d_stream);
  CHECK_ERR(err, "inflateEnd");
}

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t size) {
  size_t comprLen = 100 + 2 * compressBound(size);
  size_t uncomprLen = size;
  uint8_t *compr, *uncompr;

  /* Discard inputs larger than 1Mb. */
  static size_t kMaxSize = 1024 * 1024;

  // This test requires at least 3 bytes of input data.
  if (size <= 3 || size > kMaxSize)
    return 0;

  data = d;
  dataLen = size;
  compr = (uint8_t *)calloc(1, comprLen);
  uncompr = (uint8_t *)calloc(1, uncomprLen);

  test_flush(compr, &comprLen);
  test_sync(compr, comprLen, uncompr, uncomprLen);

  free(compr);
  free(uncompr);

  /* This function must return 0. */
  return 0;
}
