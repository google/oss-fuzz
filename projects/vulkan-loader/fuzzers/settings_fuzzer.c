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
 * Create config files for given path and data.
 */
int create_config_file(const char* config_path, const char* config_filename, const uint8_t* data, size_t size) {
  char filename[512];
  char path[256];
  char command[256];

  sprintf(path, "%s/%s", getenv("HOME"), config_path);
  sprintf(command, "mkdir -p %s", path);

  system(command);

  sprintf(filename, "%s/%s", path, config_filename);

  FILE *fp = fopen(filename, "wb");
  if (!fp) {
    return 1;
  }
  fwrite(data, size, 1, fp);
  fclose(fp);

  return 0;
}

/*
 * Remove config file
 */
void remove_config_file(const char* config_path, const char* config_filename) {
  char filename[512];
  sprintf(filename, "%s/%s/%s", getenv("HOME"), config_path, config_filename);
  unlink(filename);
}

/*
 * Targets the settings parser.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  setenv("HOME", "/tmp", 1);

  // Create loader configuration file
  int result = create_config_file(".local/share/vulkan/loader_settings.d", "vk_loader_settings.json", data, size);
  if (result) {
    return 0;
  }

  update_global_loader_settings();
  update_global_loader_settings();
  get_current_settings_and_lock(NULL);
  release_current_settings_lock(NULL);
  struct loader_layer_list settings_layers = {0};

  bool should_search_for_other_layers = true;
  get_settings_layers(NULL, &settings_layers, &should_search_for_other_layers);
  // Free allocated memory
  loader_delete_layer_list_and_properties(NULL, &settings_layers);
  should_skip_logging_global_messages(0);
  update_global_loader_settings();
  teardown_global_loader_settings();

  // Clean up config file
  remove_config_file(".local/share/vulkan/loader_settings.d", "vk_loader_settings.json");

  return 0;
}
