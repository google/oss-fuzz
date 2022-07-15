/* Copyright 2021 Google LLC
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

/*
 * We convert dlltool.c into a header file to make convenient for fuzzing.
 * We do this for several of the binutils applications when creating
 * the binutils fuzzers.
 */
#include "fuzz_windres.h"

/*
 *
 * This fuzzer performs initial checks on the data
 * that are similar to what the windres application does, however
 * with the caveat that windres will fatally exit and the fuzzer simply returns, i.e.
 * fuzzing continues. The purpose is to enable further analysis.
 *
 * Down the line, perhaps it makes sense to chage binutils to have less fatals and
 * more graceful exits. This would be useful for the fuzzing.
 */

static enum res_format
fuzz_format_check_from_mem(const uint8_t *data, size_t size) {
  int magic;
  if (size < 2) {
	return RES_FORMAT_UNKNOWN;
  }
  if (data[0] == 0x4d && data[1] == 0x5a) {
	return RES_FORMAT_COFF;
  }
  magic = data[0] << 8 | data[1];
  if (magic == 0x14c || magic == 0x166 || magic == 0x184 || magic == 0x268 || magic == 0x1f0 || magic == 0x290) {
      return RES_FORMAT_COFF;
  }
	return RES_FORMAT_UNKNOWN;
}

int
fuzz_check_coff_rsrc (const char *filename, const char *target)
{
  int retval = 0;
  bfd *abfd;
  windres_bfd wrbfd;
  asection *sec;
  bfd_size_type size;

  abfd = bfd_openr (filename, target);
  if (abfd == NULL) {
    return 0;
  }

  if (! bfd_check_format (abfd, bfd_object)) {
	  retval = 0;
	  goto cleanup;
    }

  sec = bfd_get_section_by_name (abfd, ".rsrc");
  if (sec == NULL) {
	  retval = 0;
	  goto cleanup;
    }

  set_windres_bfd (&wrbfd, abfd, sec, WR_KIND_BFD);
  size = bfd_section_size (sec);
  if (size > (bfd_size_type) get_file_size (filename)) {
	  retval = 0;
	  goto cleanup;
  }

  retval = 1;
cleanup:
  bfd_close (abfd);
  return retval;
}


int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  enum res_format input_format;
   input_format = fuzz_format_check_from_mem(data, size);;
	if (input_format != RES_FORMAT_COFF) {
		return 0;
	}

  char filename[256];
  sprintf(filename, "/tmp/libfuzzer.%d", getpid());
  FILE *fp = fopen(filename, "wb");
  if (!fp) {
    return 0;
  }
  fwrite(data, size, 1, fp);
  fclose(fp);


  program_name = "fuzz_windres";

  // For now we only check FORMAT_COFF, this can be extended to
  // the two additional formats later.
  if (input_format == RES_FORMAT_COFF) {
	  if (fuzz_check_coff_rsrc(filename, NULL) != 0) {
		  read_coff_rsrc (filename, NULL);
	  }
  }

  unlink(filename);
  return 0;
}
