/* Copyright 2025 Google LLC
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

uint8_t *global_fuzz_data;
size_t global_size;

char *callback1 = NULL;
char *callback2 = NULL;
char *callback3 = NULL;
char *callback4 = NULL;

void fuzz_init(const uint8_t *data, size_t size) {
    global_fuzz_data = (uint8_t *)data;
    global_size = size;
    
    callback1 = NULL;
    callback2 = NULL;
    callback3 = NULL;
    callback4 = NULL;
}

#ifdef ENABLE_FILE_CALLBACK
void create_callback_file(const char *filename) {
  fprintf(stderr, "create_callback_file: Creating file %s\n", filename);
  FILE *fp = fopen(filename, "wb");
  if (!fp) {
    return;
  }
  fwrite(global_fuzz_data, global_size, 1, fp);
  fclose(fp);

  if (callback1 == NULL) {
    callback1 = strdup(filename);
  } else if (callback2 == NULL) {
    callback2 = strdup(filename);
  } else if (callback3 == NULL) {
    callback3 = strdup(filename);
  } else if (callback4 == NULL) {
    callback4 = strdup(filename);
  } else {
    fprintf(stderr, "create_callback_file: Too many callbacks created, ignoring %s\n", filename);
  }
}

#else
void create_callback_file(const char *filename) {}
#endif

void fuzz_cleanup() {
  if (callback1) {
 unlink(callback1);    
    free(callback1);
   
    callback1 = NULL;
  }
  if (callback2) {
 unlink(callback2);    
    free(callback2);
    callback2 = NULL;
  }
  if (callback3) {
 unlink(callback3);      
    free(callback3);
    callback3 = NULL;
  }
  if (callback4) {
     unlink(callback4);
    free(callback4);
    callback4 = NULL;
  }
}