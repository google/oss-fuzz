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
#include <config.h>

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>

#include "bluetooth.h"
#include "sdp.h"
#include "sdp_lib.h"
#include "hci_lib.h"


int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  int to_copy = size;
  uint8_t features[8];

  if (size > 8) {
    to_copy = 8;
  }

  char *null_terminated = malloc(to_copy+1);
  memcpy(null_terminated, data, to_copy);
  null_terminated[to_copy] = '\0';
/*
  char *tmp = lmp_featurestostr(features, null_terminated, to_copy);
  if (tmp) {
    free(tmp);
  }
*/
  char *tmp = NULL;

  size -= to_copy;
  data += to_copy;

  /*
  uint8_t cmds[64];
  bzero(cmds, 64);
  for (int i = 0; i < 64 && i < size; i++) {
    cmds[i] = data[i];
  }
  tmp = hci_commandstostr(cmds, NULL, 0);
  if (tmp) {
    free(tmp);
  }
  */
  if (size > 4) {
    uint16_t id = *(uint16_t*)data;
    bt_compidtostr(id);
  }

  free(null_terminated);
  return 0;
}
