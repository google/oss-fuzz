/* Copyright 2026 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Fuzz test for image_decomp() - multi-format decompressor.
 */

#include <image.h>
#include <malloc.h>
#include <test/fuzz.h>

#define DECOMP_BUF_SIZE (1 * 1024 * 1024)  /* 1 MB output limit */

static void *decomp_buf;

static int fuzz_image_decomp(const uint8_t *data, size_t size)
{
	ulong load_end;
	int comp;

	if (size < 2)
		return 0;

	/* First byte selects compression type */
	comp = (data[0] % (IH_COMP_COUNT - 1)) + 1;
	data++;
	size--;

	if (!decomp_buf) {
		decomp_buf = malloc(DECOMP_BUF_SIZE);
		if (!decomp_buf)
			return 0;
	}

	image_decomp(comp, 0, 0, IH_TYPE_KERNEL,
		     decomp_buf, (void *)data, size,
		     DECOMP_BUF_SIZE, &load_end);

	return 0;
}
FUZZ_TEST(fuzz_image_decomp, 0);
