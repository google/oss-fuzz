/* Copyright 2022 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "config.h"

#include "libglnx.h"
#include "bsdiff/bsdiff.h"
#include "bsdiff/bspatch.h"
#include <glib.h>
#include <stdlib.h>
#include <gio/gio.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static int
bzdiff_write (struct bsdiff_stream* stream, const void* buffer, int size)
{
  GOutputStream *out = stream->opaque;
  if (! g_output_stream_write (out,
                               buffer,
                               size,
                               NULL,
                               NULL)) {
    return -1;
  }

  return 0;
}


int
LLVMFuzzerTestOneInput (const uint8_t *data,
                        size_t         size)
{
#define NEW_SIZE (512+24)

  struct bsdiff_stream bsdiff_stream;
  struct bspatch_stream bspatch_stream;
  int i;
  g_autofree guint8 *old = g_new (guint8, size);
  g_autofree guint8 *new = g_new (guint8, NEW_SIZE);
  g_autofree guint8 *new_generated = g_new0 (guint8, NEW_SIZE);
  g_autoptr(GOutputStream) out = g_memory_output_stream_new_resizable ();
  g_autoptr(GInputStream) in = NULL;

  new[0] = 'A';
  for (i = 0; i < size; i++) {
    old[i] = data[i];
  }
  for (i = 0; i < NEW_SIZE; i++) {
    new[i] = i;
  }

  bsdiff_stream.malloc = malloc;
  bsdiff_stream.free = free;
  bsdiff_stream.write = bzdiff_write;
  bsdiff_stream.opaque = out;
  bsdiff (old, size, new, NEW_SIZE, &bsdiff_stream);

  return 0;
}
