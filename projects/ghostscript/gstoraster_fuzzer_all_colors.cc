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

#include "gstoraster_fuzzlib.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (size == 0) {
		return 0;
	}
	// Modulo the possibilities: https://github.com/ArtifexSoftware/ghostpdl/blob/8c97d5adce0040ac38a1fb4d7954499c65f582ff/cups/libs/cups/raster.h#L102
	// This enables the fuzzer to explore all color schemes
	int color_scheme = ((int)data[0] % 63);
	data++;
	size--;

	gs_to_raster_fuzz(data, size, color_scheme);
	return 0;
}
