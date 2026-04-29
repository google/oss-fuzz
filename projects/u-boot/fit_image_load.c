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
 * Fuzz test for fit_image_load() - FIT image loader.
 */

#include <image.h>
#include <mapmem.h>
#include <linux/libfdt.h>
#include <test/fuzz.h>

static int fuzz_fit_image_load(const uint8_t *data, size_t size)
{
	struct bootm_headers images = {};
	const char *fit_uname = NULL;
	const char *fit_uname_config = NULL;
	ulong data_ptr, len;
	ulong addr;

	if (size < sizeof(struct fdt_header))
		return 0;

	/* Quick check: is it a valid FDT? FIT images are FDT blobs. */
	if (fdt_check_header(data) != 0)
		return 0;

	/* Map fuzz data into u-boot's address space */
	addr = map_to_sysmem((void *)data);

	fit_image_load(&images, addr, &fit_uname, &fit_uname_config,
		       IH_ARCH_DEFAULT, IH_TYPE_KERNEL, 0,
		       FIT_LOAD_IGNORED, &data_ptr, &len);

	return 0;
}
FUZZ_TEST(fuzz_fit_image_load, 0);
