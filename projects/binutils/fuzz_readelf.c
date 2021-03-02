/* Copyright 2020 Google Inc.

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

#include "readelf.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char filename[256];
	sprintf(filename, "/tmp/libfuzzer.%d", getpid());

	FILE *fp = fopen(filename, "wb");
	if (!fp)
		return 0;

	fwrite(data, size, 1, fp);
	fclose(fp);
	do_syms = TRUE;
	do_reloc = TRUE;
	do_unwind = TRUE;
	do_dynamic = TRUE;
	do_header = TRUE;
	do_sections = TRUE;
	do_section_groups = TRUE;
	do_segments = TRUE;
	do_version = TRUE;
	do_histogram = TRUE;
	do_arch = TRUE;
	do_notes = TRUE;

    // Main fuzz entrypoint
	process_file(filename);

	unlink(filename);

	free (dump_ctf_symtab_name);
	dump_ctf_symtab_name = NULL;
	free (dump_ctf_strtab_name);
	dump_ctf_strtab_name = NULL;
	free (dump_ctf_parent_name);
	dump_ctf_parent_name = NULL;

	return 0;
}
