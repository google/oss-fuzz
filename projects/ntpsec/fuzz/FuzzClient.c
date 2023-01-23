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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ntpd.h"

#define kMinInputLength 20
#define kMaxInputLength 1024

bool nts_client_process_response_core(uint8_t *buff, int transferred, struct peer* peer);

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {//ntpsec/tests/ntpd/nts_client.c

    if (Size < kMinInputLength || Size > kMaxInputLength){
        return 0;
    }

	struct peer peer;

	peer.nts_state.aead = 42; /* Dummy init values */
	peer.nts_state.cookielen = 0;
	peer.nts_state.writeIdx = 0;
	peer.nts_state.count = 0;

	peer.srcadr.sa4.sin_family = AF_INET;
	peer.srcadr.sa4.sin_port = htons(9999);
	peer.srcadr.sa4.sin_addr.s_addr= htonl(0x04030201);

	return nts_client_process_response_core((uint8_t*)Data,Size, &peer);
}
