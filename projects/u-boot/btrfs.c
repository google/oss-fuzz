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
 * Fuzz test for BTRFS filesystem parser.
 */

#include <command.h>
#include <os.h>
#include <test/fuzz.h>

#define FUZZ_DISK_PATH "/tmp/fuzz_btrfs.img"

static int fuzz_btrfs(const uint8_t *data, size_t size)
{
	int fd;

	if (size < 512)
		return 0;

	fd = os_open(FUZZ_DISK_PATH, OS_O_WRONLY | OS_O_CREAT | OS_O_TRUNC);
	if (fd < 0)
		return 0;
	os_write(fd, data, size);
	os_close(fd);

	run_command("host bind 0 " FUZZ_DISK_PATH, 0);
	run_command("ls host 0:0 /", 0);
	run_command("host unbind 0", 0);

	return 0;
}
FUZZ_TEST(fuzz_btrfs, 0);
