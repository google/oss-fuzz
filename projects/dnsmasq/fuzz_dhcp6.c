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
  static int val213 = 0;
void FuzzDhcp(const uint8_t **data2, size_t *size2) {
  const uint8_t *data = *data2;
  size_t size = *size2;
  

  time_t now;
  int pxe_fd = 0;

  struct iovec *dhpa = malloc(sizeof(struct iovec));
  if (dhpa == NULL) return;

  char *content = malloc(300);
  if (content == NULL) {
    free(dhpa);
    return;
  }
  
  dhpa->iov_base = content;
  dhpa->iov_len = 300;

  daemon->dhcp_packet = *dhpa;

  syscall_data = data;
  syscall_size = size;

  dhcp6_packet(now);

  free(dhpa);
  free(content);
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

		FuzzDhcp(&data, &size);

    cache_start_insert();
    fuzz_blockdata_cleanup();
  }

  // Free data in mini garbage collector.
  gb_cleanup();

  return 0;
}
