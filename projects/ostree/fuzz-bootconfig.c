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
 * Fuzz target for ostree bootconfig parsing.
 * Exercises OstreeBootconfigParser which parses bootloader entry files
 * with key=value pairs, overlay initrds, and tries counter parsing.
 */

#include "config.h"
#include <glib.h>
#include <gio/gio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>

#include "libglnx.h"
#include "ostree.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (size < 1 || size > 65536)
    return 0;

  g_autoptr(GError) error = NULL;

  /* Create a temp file with the fuzz data as a bootconfig file.
   * Use a filename that exercises the tries counter parser.
   */
  g_autofree char *tmpdir = g_dir_make_tmp("fuzz-bootconfig-XXXXXX", &error);
  if (!tmpdir)
    return 0;

  /* Build a filename with potential tries counter suffix from fuzz data */
  g_autofree char *filename = NULL;
  if (size >= 2 && data[0] == '+')
    {
      /* Use first bytes as the filename suffix to exercise parse_bootloader_tries */
      size_t name_len = 0;
      for (name_len = 0; name_len < size && name_len < 64; name_len++)
        {
          if (data[name_len] == '\0' || data[name_len] == '/')
            break;
        }
      g_autofree char *name_part = g_strndup((const char *)data, name_len);
      filename = g_strdup_printf("entry%s.conf", name_part);
      data += name_len;
      size -= name_len;
    }
  else
    {
      filename = g_strdup("entry+3-1.conf");
    }

  g_autofree char *filepath = g_build_filename(tmpdir, filename, NULL);
  if (!g_file_set_contents(filepath, (const char *)data, size, &error))
    {
      g_rmdir(tmpdir);
      return 0;
    }

  g_autoptr(OstreeBootconfigParser) parser = ostree_bootconfig_parser_new();
  ostree_bootconfig_parser_parse_at(parser, AT_FDCWD, filepath, NULL, &error);
  g_clear_error(&error);

  if (parser)
    {
      /* Exercise the getters */
      ostree_bootconfig_parser_get_tries_left(parser);
      ostree_bootconfig_parser_get_tries_done(parser);
      ostree_bootconfig_parser_get(parser, "title");
      ostree_bootconfig_parser_get(parser, "linux");
      ostree_bootconfig_parser_get(parser, "initrd");
      ostree_bootconfig_parser_get(parser, "options");

      /* Exercise write-back */
      g_autofree char *outpath = g_build_filename(tmpdir, "output.conf", NULL);
      ostree_bootconfig_parser_write_at(parser, AT_FDCWD, outpath, NULL, &error);
      g_clear_error(&error);
      unlink(outpath);

      /* Exercise clone */
      g_autoptr(OstreeBootconfigParser) cloned = ostree_bootconfig_parser_clone(parser);
    }

  unlink(filepath);
  g_rmdir(tmpdir);
  return 0;
}
