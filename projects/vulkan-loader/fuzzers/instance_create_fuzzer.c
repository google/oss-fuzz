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
 * Targets the instance creation.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char filename[512];
  char path[256];
  char command[256];

  sprintf(path, "%s/.local/share/vulkan/implicit_layer.d", getenv("HOME"));
  sprintf(command, "mkdir -p %s", path);

  system(command);

  sprintf(filename, "%s/complex_layer.json", path);

  FILE *fp = fopen(filename, "wb");
  if (!fp) {
    return 0;
  }
  fwrite(data, size, 1, fp);
  fclose(fp);

  sprintf(path, "%s/.local/share/vulkan/loader_settings.d", getenv("HOME"));
  sprintf(command, "mkdir -p %s", path);
  
  system(command);

  sprintf(filename, "%s/vk_loader_settings.json", path);

  fp = fopen(filename, "wb");
  if (!fp) {
    return 0;
  }
  fwrite(data, size, 1, fp);
  fclose(fp);

  sprintf(path, "%s/.local/share/vulkan/icd.d", getenv("HOME"));
  sprintf(command, "mkdir -p %s", path);
  
  system(command);

  sprintf(filename, "%s/icd_test.json", path);

  fp = fopen(filename, "wb");
  if (!fp) {
    return 0;
  }
  fwrite(data, size, 1, fp);
  fclose(fp);

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
  unlink(filename);

  return 0;
}
