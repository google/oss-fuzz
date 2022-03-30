/* Copyright 2021 Google LLC
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

#include "fuzz_header.h"

/* 
 * Targets answer_auth
 */
void FuzzAuth(const uint8_t **data2, size_t *size2) {
  const uint8_t *data = *data2;
  size_t size = *size2;
  
  int i1 = get_int(&data, &size);
  int i2 = get_int(&data, &size);
  int i3 = get_int(&data, &size);

  if (size > (sizeof(struct dns_header) +50)) {
    char *new_data = malloc(size+1);
    memset(new_data, 0, size);
    memcpy(new_data, data, size);
    new_data[size] = '\0';
    pointer_arr[pointer_idx++] = (void*)new_data;

    time_t now;
		union mysockaddr peer_addr;
		answer_auth((struct dns_header *)new_data, new_data + size, size, now, &peer_addr, i1, i2, i3);
  }
}

/*
 * Fuzzer entrypoint.
 */ 
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  daemon = NULL;
  if (size < 1) {
    return 0;
  }

  // Initialize mini garbage collector
  gb_init();

  // Get a value we can use to decide which target to hit.
  int i = (int)data[0];
  data += 1;
  size -= 1;

  int succ = init_daemon(&data, &size);

  if (succ == 0) {
    cache_init();
    blockdata_init();

		FuzzAuth(&data, &size);

    cache_start_insert();
    fuzz_blockdata_cleanup();
  }

  // Free data in mini garbage collector.
  gb_cleanup();

  return 0;
}
