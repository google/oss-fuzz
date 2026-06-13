// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include <libdeflate.h>
#include <stdint.h>
#include <stdlib.h>

/* Fuzz gzip decompression. */
int LLVMFuzzerTestOneInput(const uint8_t *in, size_t insize)
{
	size_t outsize_avail = 3 * insize + 4096;
	uint8_t *out;
	struct libdeflate_decompressor *d;

	out = malloc(outsize_avail);
	if (!out)
		return 0;

	d = libdeflate_alloc_decompressor();
	if (d) {
		libdeflate_gzip_decompress(d, in, insize, out, outsize_avail, NULL);
		libdeflate_free_decompressor(d);
	}
	free(out);
	return 0;
}
