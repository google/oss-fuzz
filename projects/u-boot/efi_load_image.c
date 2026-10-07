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
 * Fuzz test for efi_load_image() - feeds random data as a PE image buffer
 * into the EFI image loader.
 */

#include <efi_loader.h>
#include <test/fuzz.h>

static int fuzz_efi_load_image(const uint8_t *data, size_t size)
{
	efi_handle_t image_handle = NULL;

	if (size == 0)
		return 0;

	/* Initialize EFI subsystem on first call */
	if (efi_obj_list_initialized != EFI_SUCCESS)
		efi_init_obj_list();

	/* Call efi_load_image with fuzz data as a PE image buffer */
	EFI_CALL(efi_load_image(false, efi_root, NULL,
				(void *)data, size, &image_handle));

	/* Clean up loaded image to prevent memory accumulation */
	if (image_handle)
		EFI_CALL(efi_unload_image(image_handle));

	return 0;
}
FUZZ_TEST(fuzz_efi_load_image, 0);
