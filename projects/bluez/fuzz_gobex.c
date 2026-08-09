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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "gobex/gobex.h"
#include "gobex/gobex-packet.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  uint8_t buf[255];
  GObexPacket *pkt;
  GError *err = NULL;
  pkt = g_obex_packet_decode(data, size, 0, G_OBEX_DATA_REF, &err);
  if (pkt != NULL) {
    /* Anything that decodes must encode */
    g_obex_packet_encode(pkt, buf, sizeof(buf));
    g_obex_packet_free(pkt);
  }

  return 0;
}
