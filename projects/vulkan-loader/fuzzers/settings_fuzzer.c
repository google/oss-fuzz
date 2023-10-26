/* Copyright 2023 Google LLC
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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "cJSON.h"
#include "loader.h"

/*
 * Targets the settings parser.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char filename[512];
  char path[256];
  char command[256];
  sprintf(path, "%s/.local/share/vulkan/loader_settings.d", getenv("HOME"));
  sprintf(command, "mkdir -p %s", path);
  
  system(command);

  sprintf(filename, "%s/vk_loader_settings.json", path);

  FILE *fp = fopen(filename, "wb");
  if (!fp) {
    return 0;
  }
  fwrite(data, size, 1, fp);
  fclose(fp);

  update_global_loader_settings();
  update_global_loader_settings();
  get_current_settings_and_lock(NULL);
  release_current_settings_lock(NULL);
  struct loader_layer_list settings_layers = {0};

  bool should_search_for_other_layers = true;
  get_settings_layers(NULL, &settings_layers, &should_search_for_other_layers);
  should_skip_logging_global_messages(0);
  update_global_loader_settings();
  teardown_global_loader_settings();

  unlink(filename);

  return 0;
}
