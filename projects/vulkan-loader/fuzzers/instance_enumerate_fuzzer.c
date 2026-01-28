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
#include "fuzz_header.h"

#define MAX_SIZE = 64000
int LLVMFuzzerInitialize(int *argc, char ***argv) {
  setenv("HOME", "/tmp", 1);
  system("mkdir -p $HOME/.local/share/vulkan/implicit_layer.d");
  system("mkdir -p $HOME/.local/share/vulkan/loader_settings.d");
  return 0;
}

/*
 * Create config files for given path and data.
 */
int create_config_file(const char* config_path, const char* config_filename, const uint8_t* data, size_t size) {
  char filename[512];
  char path[256];


  sprintf(path, "%s/%s", getenv("HOME"), config_path);
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
 * Targets the instance extension enumeration.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

# ifdef SPLIT_INPUT
  if (size < 2*sizeof(size_t)) {
    return 0;
  }

  // Split the loaders into two different parts so the files
  // are independently seeded with fuzz data.
  size_t first_size = (*(size_t*)data) % 64000;
  size_t second_size = (*(size_t*)(data + sizeof(size_t))) % 64000;

  data += 2*sizeof(size_t); // Move past the first two integers
  size -= 2*sizeof(size_t); // Adjust size to account for the first two integers
  size_t total_size_needed = first_size + second_size;
  if (size <= total_size_needed) {
    return 0;
  }
  int result = create_config_file(".local/share/vulkan/implicit_layer.d", "complex_layer.json", data, first_size);
  if (result) {
    return 0;
  }

  data += first_size;

  result = create_config_file(".local/share/vulkan/loader_settings.d", "vk_loader_settings.json", data, second_size);
  if (result) {
    return 0;
  }
#else
  int result = create_config_file(".local/share/vulkan/implicit_layer.d", "complex_layer.json", data, size);
  if (result) {
    return 0;
  }

  result = create_config_file(".local/share/vulkan/loader_settings.d", "vk_loader_settings.json", data, size);
  if (result) {
    return 0;
  }
#endif


  //printf("Status: %d\n", (int)ms);
  setenv("VK_LOADER_LAYERS_ENABLE", "all", 1);

  uint32_t pPropertyCount = 0;
  VkResult vk_result = vkEnumerateInstanceExtensionProperties("test_auto", &pPropertyCount, NULL);
  
  if (vk_result == VK_SUCCESS) {
  
    VkExtensionProperties* pProperties = (VkExtensionProperties*)malloc(sizeof(VkExtensionProperties) * pPropertyCount); 
  
    vkEnumerateInstanceExtensionProperties("test_auto", &pPropertyCount, pProperties);
    
    free(pProperties);
  }
  // Clean up config files
  remove_config_file(".local/share/vulkan/implicit_layer.d", "complex_layer.json");
  remove_config_file(".local/share/vulkan/loader_settings.d", "vk_loader_settings.json");

  return 0;
}
