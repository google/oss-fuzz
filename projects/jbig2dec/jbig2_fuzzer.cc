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

#define ALIGNMENT 16
#define MAX_ALLOCATION (1024 * 1024 * 1024)

static uint64_t total = 0;

static void *jbig2_alloc(Jbig2Allocator *allocator, size_t size)
{
  void *ptr;

  if (size == 0)
    return NULL;

  ptr = malloc(size + ALIGNMENT);
  memcpy(ptr, &size, sizeof(size));
  total += size + ALIGNMENT;

  return (unsigned char *) ptr + ALIGNMENT;
}

static void jbig2_free(Jbig2Allocator *allocator, void *p)
{
  int size;

  if (p == NULL)
    return;

  memcpy(&size, (unsigned char *) p - ALIGNMENT, sizeof(size));
  total -= size + ALIGNMENT;
  free((unsigned char *) p - ALIGNMENT);
}

static void *jbig2_realloc(Jbig2Allocator *allocator, void *p, size_t size)
{
  unsigned char *oldp = p ? (unsigned char *) p - ALIGNMENT : NULL;

  if (size > SIZE_MAX - ALIGNMENT)
    return NULL;

  if (size > MAX_ALLOCATION - ALIGNMENT - total)
    return NULL;

  if (oldp == NULL)
  {
    if (size == 0)
      return NULL;

    p = malloc(size + ALIGNMENT);
  }
  else
  {
    int oldsize;
    memcpy(&oldsize, oldp, sizeof(oldsize));

    if (size == 0)
    {
      total -= oldsize + ALIGNMENT;
      free(oldp);
      return NULL;
    }

    p = realloc(oldp, size + ALIGNMENT);
    if (p == NULL)
      return NULL;

    total -= oldsize + ALIGNMENT;
  }

  memcpy(p, &size, sizeof(size));
  total += size + ALIGNMENT;
  return (unsigned char *) p + ALIGNMENT;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  Jbig2Allocator allocator;
  Jbig2Ctx *ctx = NULL;

  allocator.alloc = jbig2_alloc;
  allocator.free = jbig2_free;
  allocator.realloc = jbig2_realloc;

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

  return 0;
}
