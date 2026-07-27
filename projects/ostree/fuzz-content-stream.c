/* Copyright 2026 Google LLC
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

/*
 * Fuzz target for ostree content stream parsing.
 * Exercises ostree_content_stream_parse which processes file object headers
 * containing GVariant metadata (uid, gid, mode, symlink target, xattrs).
 */

#include "config.h"
#include <glib.h>
#include <gio/gio.h>
#include <string.h>
#include <stdint.h>

#include "ostree-core.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (size < 9)  /* minimum: 4 byte header size + 4 byte padding + 1 byte content */
    return 0;

  g_autoptr(GError) error = NULL;
  g_autoptr(GInputStream) input = NULL;
  g_autoptr(GFileInfo) file_info = NULL;
  g_autoptr(GVariant) xattrs = NULL;
  g_autoptr(GInputStream) content_input = NULL;

  /* Use first bit to select compressed vs uncompressed */
  gboolean compressed = (data[0] & 0x80) != 0;

  /* Mask off the selector bit from first byte so it doesn't interfere */
  g_autofree uint8_t *modified = g_memdup2(data, size);
  modified[0] &= 0x7F;

  input = g_memory_input_stream_new_from_data(
      g_memdup2(modified, size), size, g_free);

  /* Parse the content stream - trusted=FALSE for untrusted input */
  ostree_content_stream_parse(compressed,
                               input,
                               (guint64)size,
                               FALSE, /* not trusted */
                               &content_input,
                               &file_info,
                               &xattrs,
                               NULL,
                               &error);

  g_clear_error(&error);
  return 0;
}
