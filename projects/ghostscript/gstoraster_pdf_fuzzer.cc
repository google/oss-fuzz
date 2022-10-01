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

#include "gs_fuzzlib.h"

// Returns 1 if this has a valid PDF header and 0 otherwise
static int quick_check_pdf(const uint8_t *data, size_t size) {
	// PDF checks. Exit early if we don't have a valid PDF signature.
	if (size < 5) {
		return 0;
	}

	// Check PDF tag. We do this because we want to use seeds
	if (data[0] != 0x25 || data[1] != 0x50 || data[2] != 0x44 || data[3] != 0x46 || data[4] != 0x2d) {
		return 0;
	}
	return 1;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (quick_check_pdf(data, size) != 1) {
		return 0;
	}

	/* Tests using RGB color scheme */
	gs_to_raster_fuzz(data, size, 1);
	return 0;
}
