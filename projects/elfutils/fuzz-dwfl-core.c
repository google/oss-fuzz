/*
# Copyright 2021 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
*/
#include <assert.h>
#include <config.h>
#include <stdlib.h>
#include <unistd.h>
#include ELFUTILS_HEADER(dwfl)

static const Dwfl_Callbacks core_callbacks = {
	.find_elf = dwfl_build_id_find_elf,
	.find_debuginfo = dwfl_standard_find_debuginfo,
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	char name[] = "/tmp/fuzz-dwfl-core.XXXXXX";
	int fd = -1;
	ssize_t n;
	off_t offset;
	Elf *core = NULL;
	Dwfl *dwfl = NULL;

	fd = mkstemp(name);
	assert(fd >= 0);

	n = write(fd, data, size);
	assert(n == (ssize_t) size);

	offset = lseek(fd, 0, SEEK_SET);
	assert(offset == 0);

	elf_version(EV_CURRENT);
	core = elf_begin(fd, ELF_C_READ_MMAP, NULL);
	if (core == NULL)
		goto cleanup;
	dwfl = dwfl_begin(&core_callbacks);
	assert(dwfl != NULL);
	if (dwfl_core_file_report(dwfl, core, NULL) < 0)
		goto cleanup;
	if (dwfl_report_end(dwfl, NULL, NULL) != 0)
		goto cleanup;

cleanup:
	dwfl_end(dwfl);
	elf_end(core);
	close(fd);
	unlink(name);
	return 0;
}
