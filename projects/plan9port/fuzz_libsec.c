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
#include <string.h>
#include <stdlib.h>

#include <u.h>
#include <libc.h>
#include <auth.h>
#include <mp.h>
#include <libsec.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size){
	char *fuzz_der = (char *)malloc(size+1);
	if (fuzz_der == NULL){
		return 0;
	}
	memcpy(fuzz_der, data, size);
	fuzz_der[size] = '\0';
	asn1dump(fuzz_der, size);
	
	free(fuzz_der);
	return 0;
}
