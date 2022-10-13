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
#include "nts.h"

#define kMinInputLength 20
#define kMaxInputLength 1024

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {//ntpsec/tests/ntpd/nts_server.c

	if (Size < kMinInputLength || Size > kMaxInputLength){
        return 0;
    }

	int aead;
	struct BufCtl_t buf;

	aead = NO_AEAD;
	buf.next = (uint8_t*)Data;
	buf.left = Size;	

	return nts_ke_process_receive(&buf, &aead);
}
