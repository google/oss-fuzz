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
 * Targets the instance creation.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  setenv("HOME", "/tmp", 1);

  // Create implicit layer configuration file
  int result = create_config_file(".local/share/vulkan/implicit_layer.d", "complex_layer.json", data, size);
  if (result) {
    return 0;
  }
  
  // Create loader configuration file
  result = create_config_file(".local/share/vulkan/loader_settings.d", "vk_loader_settings.json", data, size);
  if (result) {
    return 0;
  }

  // Create icd configuration file
  result = create_config_file(".local/share/vulkan/icd.d", "icd_test.json", data, size);
  if (result) {
    return 0;
  }

  setenv("VK_LOADER_LAYERS_ENABLE", "all", 1);


  VkInstance inst = {0};
  char *instance_layers[] = {
    "VK_LAYER_KHRONOS_validation",
    "VK_LAYER_test_layer_1",
    "VK_LAYER_test_layer_2"
  };
  const VkApplicationInfo app = {
      .sType = VK_STRUCTURE_TYPE_APPLICATION_INFO,
      .pNext = NULL,
      .pApplicationName = "TEST_APP",
      .applicationVersion = 0,
      .pEngineName = "TEST_ENGINE",
      .engineVersion = 0,
      .apiVersion = VK_API_VERSION_1_0,
  };
  VkInstanceCreateInfo inst_info = {
      .sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO,
      .pNext = NULL,
      .pApplicationInfo = &app,
      .enabledLayerCount = 1,
      .ppEnabledLayerNames = (const char *const *)instance_layers,
      .enabledExtensionCount = 0,
      .ppEnabledExtensionNames = NULL,
  };
  VkResult err = vkCreateInstance(&inst_info, NULL, &inst);
  if (err != VK_SUCCESS) {
    goto out;
  }

  vkDestroyInstance(inst, NULL);

out:
  // Clean up config files
  remove_config_file(".local/share/vulkan/implicit_layer.d", "complex_layer.json");
  remove_config_file(".local/share/vulkan/loader_settings.d", "vk_loader_settings.json");
  remove_config_file(".local/share/vulkan/icd.d", "icd_test.json");

  return 0;
}
