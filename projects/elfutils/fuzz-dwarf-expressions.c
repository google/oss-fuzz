/* Copyright 2024 Google LLC
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

/* Fuzz harness for DWARF expression/location and source-line parsing in libdw.
 *
 * Coverage targets not reached by existing fuzzers:
 *   - dwarf_getlocation() / dwarf_getlocations()
 *                              (DW_AT_location / DW_AT_frame_base expressions)
 *   - dwarf_getsrclines()      (source-line information table)
 *   - dwarf_getabbrev() /
 *     dwarf_getabbrevattr_data() (abbreviation table traversal)
 *
 * fuzz-libelf.c covers ELF structure; fuzz-libdwfl.c covers coredump /
 * module-level DWARF via Dwfl; fuzz-dwfl-core.c covers core-file attachment.
 * None of them walk CU DIEs and exercise the above libdw APIs directly.
 */

#include <assert.h>
#include <dwarf.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "elfutils/libdw.h"
#include "system.h"


/* Walk the abbreviation table entries for the given DIE. */
static void
fuzz_abbrev (Dwarf_Die *die)
{
  Dwarf_Abbrev *abbrev = dwarf_getabbrev (die, 0, NULL);
  if (abbrev == NULL || abbrev == DWARF_END_ABBREV)
    return;

  for (size_t idx = 0; ; idx++)
    {
      unsigned int attr_name = 0;
      unsigned int form = 0;
      Dwarf_Sword impl = 0;
      if (dwarf_getabbrevattr_data (abbrev, idx, &attr_name, &form,
                                   &impl, NULL) != 0)
        break;
    }
}


/* Probe location-expression attributes on a single DIE. */
static void
fuzz_locations (Dwarf_Die *die)
{
  static const unsigned int loc_attrs[] = {
    DW_AT_location,
    DW_AT_frame_base,
    DW_AT_data_member_location,
    DW_AT_vtable_elem_location,
    DW_AT_use_location,
    DW_AT_string_length,
    DW_AT_return_addr,
    DW_AT_static_link,
  };

  for (size_t i = 0; i < sizeof (loc_attrs) / sizeof (loc_attrs[0]); i++)
    {
      Dwarf_Attribute attr;
      if (dwarf_attr (die, loc_attrs[i], &attr) == NULL)
        continue;

      /* Single-expression form. */
      Dwarf_Op *ops = NULL;
      size_t nops = 0;
      dwarf_getlocation (&attr, &ops, &nops);

      /* Location-list form (range list of expressions). */
      ptrdiff_t offset = 0;
      Dwarf_Addr base = 0, start = 0, end = 0;
      Dwarf_Op *rl_ops = NULL;
      size_t rl_nops = 0;
      while ((offset = dwarf_getlocations (&attr, offset, &base,
                                           &start, &end,
                                           &rl_ops, &rl_nops)) > 0)
        ;
    }
}


/* Exercise all target APIs on a CU root DIE. */
static void
fuzz_die (Dwarf_Die *die)
{
  fuzz_abbrev (die);
  fuzz_locations (die);

  /* Source-line table. */
  Dwarf_Lines *lines = NULL;
  size_t nlines = 0;
  dwarf_getsrclines (die, &lines, &nlines);
}


int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 4)
    return 0;

  char filename[] = "/tmp/fuzz-dwarf-expressions.XXXXXX";
  int fd = mkstemp (filename);
  assert (fd >= 0);

  ssize_t n = write_retry (fd, data, size);
  assert (n == (ssize_t) size);

  /* dwarf_begin reads via the fd; rewind so it starts at byte 0. */
  lseek (fd, 0, SEEK_SET);

  Dwarf *dbg = dwarf_begin (fd, DWARF_C_READ);
  if (dbg == NULL)
    goto cleanup;

  Dwarf_Off off = 0;
  Dwarf_Off next_off = 0;
  size_t hdr_size = 0;

  while (dwarf_nextcu (dbg, off, &next_off, &hdr_size,
                       NULL, NULL, NULL) == 0)
    {
      Dwarf_Die die;
      if (dwarf_offdie (dbg, off + hdr_size, &die) != NULL)
        fuzz_die (&die);

      if (next_off == 0)
        break;
      off = next_off;
    }

  dwarf_end (dbg);

cleanup:
  close (fd);
  unlink (filename);
  return 0;
}
