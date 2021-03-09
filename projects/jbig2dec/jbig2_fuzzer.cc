/*
# Copyright 2018 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
*/

#include <cstdint>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "jbig2.h"

#define ALIGNMENT ((size_t) 16)
#define KBYTE ((size_t) 1024)
#define MBYTE (1024 * KBYTE)
#define GBYTE (1024 * MBYTE)
#define MAX_ALLOCATION (1 * GBYTE)

static size_t used;
static size_t peak;

static void *jbig2_fuzzer_reached_limit(size_t size)
{
  fprintf(stderr, "memory: limit: %zu Mbyte used: %zu Mbyte new: %zu Mbyte: reached limit\n", MAX_ALLOCATION / MBYTE, used / MBYTE, size / MBYTE);
  return NULL;
}

static void *jbig2_fuzzer_allocation_failed(size_t size)
{
  fprintf(stderr, "memory: limit: %zu Mbyte used: %zu Mbyte new: %zu Mbyte: allocation failed\n", MAX_ALLOCATION / MBYTE, used / MBYTE, size / MBYTE);
  return NULL;
}

static void jbig2_fuzzer_check_peak(void)
{
  if (peak == 0 || used / MBYTE > peak / MBYTE) {
    peak = used;
    fprintf(stderr, "memory: limit: %zu Mbyte peak usage: %zu Mbyte\n", MAX_ALLOCATION, peak / MBYTE);
  }
}

static void jbig2_fuzzer_statistics(void)
{
  fprintf(stderr, "memory: limit: %zu Mbyte peak usage: %zu Mbyte\n", MAX_ALLOCATION / MBYTE, peak / MBYTE);

  if (used > 0 && used > MBYTE)
    fprintf(stderr, "memory: leak: %zu Mbyte\n", used / MBYTE);
  else if (used > 0)
    fprintf(stderr, "memory: leak: %zu byte\n", used);
}

static void *jbig2_fuzzer_alloc(Jbig2Allocator *allocator, size_t size)
{
  void *ptr;

  if (size == 0)
    return NULL;
  if (size > MAX_ALLOCATION - ALIGNMENT - used)
    return jbig2_fuzzer_reached_limit(size + ALIGNMENT);

  ptr = malloc(size + ALIGNMENT);
  if (ptr == NULL)
    return jbig2_fuzzer_allocation_failed(size + ALIGNMENT);

  memcpy(ptr, &size, sizeof(size));
  used += size + ALIGNMENT;

  jbig2_fuzzer_check_peak();

  return (unsigned char *) ptr + ALIGNMENT;
}

static void jbig2_fuzzer_free(Jbig2Allocator *allocator, void *p)
{
  int size;

  if (p == NULL)
    return;

  memcpy(&size, (unsigned char *) p - ALIGNMENT, sizeof(size));
  used -= size + ALIGNMENT;
  free((unsigned char *) p - ALIGNMENT);
}

static void *jbig2_fuzzer_realloc(Jbig2Allocator *allocator, void *p, size_t size)
{
  unsigned char *oldp = p ? (unsigned char *) p - ALIGNMENT : NULL;

  if (size > SIZE_MAX - ALIGNMENT)
    return NULL;

  if (oldp == NULL)
  {
    if (size == 0)
      return NULL;
    if (size > MAX_ALLOCATION - ALIGNMENT - used)
      return jbig2_fuzzer_reached_limit(size + ALIGNMENT);

    p = malloc(size + ALIGNMENT);
    if (p == NULL)
      return jbig2_fuzzer_allocation_failed(size + ALIGNMENT);
  }
  else
  {
    int oldsize;
    memcpy(&oldsize, oldp, sizeof(oldsize));

    if (size == 0)
    {
      used -= oldsize + ALIGNMENT;
      free(oldp);
      return NULL;
    }

    if (size > MAX_ALLOCATION - used + oldsize)
      return jbig2_fuzzer_reached_limit(size + ALIGNMENT);

    p = realloc(oldp, size + ALIGNMENT);
    if (p == NULL)
      return jbig2_fuzzer_allocation_failed(size + ALIGNMENT);

    used -= oldsize + ALIGNMENT;
  }

  memcpy(p, &size, sizeof(size));
  used += size + ALIGNMENT;

  jbig2_fuzzer_check_peak();

  return (unsigned char *) p + ALIGNMENT;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  Jbig2Allocator allocator;
  Jbig2Ctx *ctx = NULL;

  used = 0;
  peak = 0;

  allocator.alloc = jbig2_fuzzer_alloc;
  allocator.free = jbig2_fuzzer_free;
  allocator.realloc = jbig2_fuzzer_realloc;

  ctx = jbig2_ctx_new(&allocator, (Jbig2Options) 0, NULL, NULL, NULL);
  if (jbig2_data_in(ctx, data, size) == 0)
  {
    if (jbig2_complete_page(ctx) == 0)
    {
      Jbig2Image *image = jbig2_page_out(ctx);
      if (image != NULL)
      {
        int sum = 0;
        for (int i = 0; i < image->height * image->stride; i++)
          sum += image->data[i];
        printf("sum of image data bytes: %d\n", sum);
      }
      jbig2_release_page(ctx, image);
    }
  }
  jbig2_ctx_free(ctx);

  jbig2_fuzzer_statistics();

  return 0;
}
