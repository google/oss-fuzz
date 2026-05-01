/*
# Copyright 2026 Google LLC
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

#include <mupdf/fitz.h>

#define ALIGNMENT ((size_t) 16)
#define KBYTE ((size_t) 1024)
#define MBYTE (1024 * KBYTE)
#define GBYTE (1024 * MBYTE)
#define MAX_ALLOCATION (1 * GBYTE)

static size_t used;

static void *fz_limit_reached(size_t oldsize, size_t size)
{
  if (oldsize == 0)
    fprintf(stderr, "limit: %zu Mbyte used: %zu Mbyte allocation: %zu: limit reached\n", MAX_ALLOCATION / MBYTE, used / MBYTE, size);
  else
    fprintf(stderr, "limit: %zu Mbyte used: %zu Mbyte reallocation: %zu -> %zu: limit reached\n", MAX_ALLOCATION / MBYTE, used / MBYTE, oldsize, size);
  fflush(0);
  return NULL;
}

static void *fz_malloc_image(void *opaque, size_t size)
{
  char *ptr = NULL;

  if (size == 0)
    return NULL;
  if (size > SIZE_MAX - ALIGNMENT)
    return NULL;
  if (size + ALIGNMENT > MAX_ALLOCATION - used)
    return fz_limit_reached(0, size + ALIGNMENT);

  ptr = (char *) malloc(size + ALIGNMENT);
  if (ptr == NULL)
    return NULL;

  memcpy(ptr, &size, sizeof(size));
  used += size + ALIGNMENT;

  return ptr + ALIGNMENT;
}

static void fz_free_image(void *opaque, void *ptr)
{
  size_t size;

  if (ptr == NULL)
    return;
  if (ptr < (void *) ALIGNMENT)
    return;

  ptr = (char *) ptr - ALIGNMENT;
  memcpy(&size, ptr, sizeof(size));

  used -= size + ALIGNMENT;
  free(ptr);
}

static void *fz_realloc_image(void *opaque, void *old, size_t size)
{
  size_t oldsize;
  char *ptr;

  if (old == NULL)
    return fz_malloc_image(opaque, size);
  if (old < (void *) ALIGNMENT)
    return NULL;

  if (size == 0) {
    fz_free_image(opaque, old);
    return NULL;
  }
  if (size > SIZE_MAX - ALIGNMENT)
    return NULL;

  old = (char *) old - ALIGNMENT;
  memcpy(&oldsize, old, sizeof(oldsize));

  if (size + ALIGNMENT > MAX_ALLOCATION - used + oldsize + ALIGNMENT)
    return fz_limit_reached(oldsize + ALIGNMENT, size + ALIGNMENT);

  ptr = (char *) realloc(old, size + ALIGNMENT);
  if (ptr == NULL)
    return NULL;

  used -= oldsize + ALIGNMENT;
  memcpy(ptr, &size, sizeof(size));
  used += size + ALIGNMENT;

  return ptr + ALIGNMENT;
}

static fz_alloc_context fz_alloc_image =
{
  NULL,
  fz_malloc_image,
  fz_realloc_image,
  fz_free_image
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  fz_context *ctx;
  fz_buffer *buf = NULL;
  fz_image *image = NULL;
  fz_pixmap *pix = NULL;

  if (size < 8 || size > 4 * MBYTE)
    return 0;

  used = 0;

  ctx = fz_new_context(&fz_alloc_image, nullptr, FZ_STORE_DEFAULT);
  if (ctx == NULL)
    return 0;

  fz_var(buf);
  fz_var(image);
  fz_var(pix);

  fz_try(ctx) {
    buf = fz_new_buffer_from_copied_data(ctx, data, size);
    image = fz_new_image_from_buffer(ctx, buf);
    pix = fz_get_pixmap_from_image(ctx, image, NULL, NULL, NULL, NULL);
  }
  fz_always(ctx) {
    fz_drop_pixmap(ctx, pix);
    fz_drop_image(ctx, image);
    fz_drop_buffer(ctx, buf);
  }
  fz_catch(ctx) {
  }

  fz_flush_warnings(ctx);
  fz_drop_context(ctx);

  return 0;
}
