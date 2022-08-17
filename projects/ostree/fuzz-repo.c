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
#include <glib-object.h>
#include <libglnx.h>
#include <locale.h>

#include "ostree-autocleanups.h"
#include "ostree-types.h"

#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

typedef struct
{
  GLnxTmpDir tmpdir;
} Fixture;


int
setup (Fixture       *fixture,
       gconstpointer  test_data)
{
  g_autoptr(GError) error = NULL;
  if (! glnx_mkdtemp ("test-repo-XXXXXX", 0700, &fixture->tmpdir, &error)) {
    return 1;
  }
  return 0;
}

void
teardown (Fixture       *fixture,
          gconstpointer  test_data)
{
 
  (void) glnx_tmpdir_delete (&fixture->tmpdir, NULL, NULL);
}

void
payload (Fixture         *fixture,
         const uint8_t   *data,
         size_t           size)
{
  g_autoptr (GKeyFile) config = NULL;
  g_autoptr(GError) error = NULL;
  guint64 bytes = 0;

  g_autoptr(OstreeRepo) repo = ostree_repo_create_at (fixture->tmpdir.fd,
                                                      ".",
                                                      OSTREE_REPO_MODE_ARCHIVE,
                                                      NULL,
                                                      NULL,
                                                      &error);

  config = ostree_repo_copy_config (repo);

  g_key_file_remove_key (config, "core", "min-free-space-size", NULL);
  
  char *m1 = malloc(size+1);
  memcpy(m1, data, size);
  m1[size] = '\0';

  g_key_file_set_string (config, m1, m1, m1);

  ostree_repo_write_config (repo, config, &error);
  ostree_repo_reload_config (repo, NULL, &error);
  ostree_repo_get_min_free_space_bytes (repo, &bytes, &error);

  free(m1);
}

int
LLVMFuzzerTestOneInput (const uint8_t *data,
                       size_t          size)
{
  Fixture ft;
  g_auto(GLnxTmpDir) ret_tmpdir = { 0, };
  ft.tmpdir = ret_tmpdir;
  if (setup(&ft, NULL) == 1) {
    return 0;
  }

  payload(&ft, data, size);
  teardown(&ft, NULL);
  return 0;
}
