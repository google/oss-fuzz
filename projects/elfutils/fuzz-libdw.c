/* Copyright 2026 Google LLC
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

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "libdw.h"
#include "libelf.h"
#include "dwarf.h"

static int
macro_callback (Dwarf_Macro *macro, void *arg)
{
  unsigned int opcode;
  dwarf_macro_opcode (macro, &opcode);

  size_t paramcnt;
  dwarf_macro_getparamcnt (macro, &paramcnt);

  Dwarf_Word p1;
  dwarf_macro_param1 (macro, &p1);

  int *count = (int *) arg;
  (*count)++;
  if (*count > 256)
    return DWARF_CB_ABORT;
  return DWARF_CB_OK;
}

static int
pubnames_callback (Dwarf *dbg, Dwarf_Global *gl, void *arg)
{
  (void) dbg;
  (void) gl;
  int *count = (int *) arg;
  (*count)++;
  if (*count > 256)
    return DWARF_CB_ABORT;
  return DWARF_CB_OK;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 64 || size > 1048576)
    return 0;

  elf_version (EV_CURRENT);

  char *buf = malloc (size);
  if (buf == NULL)
    return 0;
  memcpy (buf, data, size);

  Elf *elf = elf_memory (buf, size);
  if (elf == NULL)
    {
      free (buf);
      return 0;
    }

  Dwarf *dbg = dwarf_begin_elf (elf, DWARF_C_READ, NULL);
  if (dbg == NULL)
    {
      elf_end (elf);
      free (buf);
      return 0;
    }

  /* Iterate all CUs, DIEs, and attributes.  */
  Dwarf_CU *cu = NULL;
  Dwarf_Die cudie, child;
  while (dwarf_get_units (dbg, cu, &cu, NULL, NULL, &cudie, NULL) == 0)
    {
      dwarf_tag (&cudie);
      dwarf_diename (&cudie);
      dwarf_haschildren (&cudie);

      Dwarf_Addr addr;
      Dwarf_Word uval;
      dwarf_lowpc (&cudie, &addr);
      dwarf_highpc (&cudie, &addr);
      dwarf_entrypc (&cudie, &addr);

      /* Source lines.  */
      Dwarf_Lines *lines = NULL;
      size_t nlines = 0;
      if (dwarf_getsrclines (&cudie, &lines, &nlines) == 0)
	{
	  for (size_t i = 0; i < nlines && i < 1024; i++)
	    {
	      Dwarf_Line *line = dwarf_onesrcline (lines, i);
	      if (line != NULL)
		{
		  Dwarf_Addr laddr;
		  int lineno, col;
		  bool flag;
		  unsigned int uival;
		  dwarf_lineaddr (line, &laddr);
		  dwarf_lineno (line, &lineno);
		  dwarf_linecol (line, &col);
		  dwarf_linebeginstatement (line, &flag);
		  dwarf_lineendsequence (line, &flag);
		  dwarf_lineblock (line, &flag);
		  dwarf_lineprologueend (line, &flag);
		  dwarf_lineepiloguebegin (line, &flag);
		  dwarf_lineisa (line, &uival);
		  dwarf_linediscriminator (line, &uival);
		  dwarf_linesrc (line, NULL, NULL);
		}
	    }
	}

      /* Source files.  */
      Dwarf_Files *files = NULL;
      size_t nfiles = 0;
      if (dwarf_getsrcfiles (&cudie, &files, &nfiles) == 0)
	{
	  for (size_t i = 0; i < nfiles && i < 256; i++)
	    dwarf_filesrc (files, i, NULL, NULL);

	  const char *const *dirs;
	  size_t ndirs;
	  dwarf_getsrcdirs (files, &dirs, &ndirs);
	}

      /* Macros.  */
      int macro_count = 0;
      dwarf_getmacros (&cudie, macro_callback, &macro_count,
		       DWARF_GETMACROS_START);

      /* Iterate children (bounded depth and count).  */
      int depth = 0;
      int total_dies = 0;
      Dwarf_Die stack[64];

      if (dwarf_child (&cudie, &child) == 0)
	{
	  stack[0] = child;
	  depth = 1;

	  while (depth > 0 && total_dies < 4096)
	    {
	      Dwarf_Die *cur = &stack[depth - 1];
	      total_dies++;

	      dwarf_tag (cur);
	      dwarf_diename (cur);
	      dwarf_haschildren (cur);

	      Dwarf_Attribute at;
	      if (dwarf_attr (cur, DW_AT_name, &at) != NULL)
		dwarf_formstring (&at);
	      if (dwarf_attr (cur, DW_AT_type, &at) != NULL)
		{
		  Dwarf_Die ref;
		  dwarf_formref_die (&at, &ref);
		}
	      if (dwarf_attr (cur, DW_AT_location, &at) != NULL)
		{
		  Dwarf_Op *expr;
		  size_t nexpr;
		  dwarf_getlocation (&at, &expr, &nexpr);
		  dwarf_getlocation_addr (&at, 0, &expr, &nexpr, 1);
		}
	      if (dwarf_attr (cur, DW_AT_ranges, &at) != NULL)
		{
		  Dwarf_Addr base, start, end;
		  ptrdiff_t roff = 0;
		  int rcount = 0;
		  while ((roff = dwarf_ranges (cur, roff, &base,
					       &start, &end)) > 0
			 && rcount++ < 256)
		    ;
		}

	      dwarf_bytesize (cur);
	      dwarf_bitsize (cur);
	      dwarf_bitoffset (cur);
	      dwarf_srclang (cur);
	      dwarf_arrayorder (cur);
	      dwarf_aggregate_size (cur, &uval);

	      Dwarf_Die next_child;
	      if (depth < 63 && dwarf_child (cur, &next_child) == 0)
		{
		  Dwarf_Die sib;
		  if (dwarf_siblingof (cur, &sib) == 0)
		    stack[depth - 1] = sib;
		  else
		    depth--;

		  stack[depth] = next_child;
		  depth++;
		}
	      else
		{
		  Dwarf_Die sib;
		  if (dwarf_siblingof (cur, &sib) == 0)
		    stack[depth - 1] = sib;
		  else
		    depth--;
		}
	    }
	}

      /* Scopes.  */
      Dwarf_Die *scopes = NULL;
      int nscopes = dwarf_getscopes (&cudie, 0, &scopes);
      if (nscopes > 0)
	free (scopes);

      /* Pubnames.  */
      int pub_count = 0;
      dwarf_getpubnames (dbg, pubnames_callback, &pub_count, 0);
    }

  /* Aranges.  */
  Dwarf_Aranges *aranges = NULL;
  size_t naranges = 0;
  if (dwarf_getaranges (dbg, &aranges, &naranges) == 0)
    {
      for (size_t i = 0; i < naranges && i < 1024; i++)
	{
	  Dwarf_Arange *ar = dwarf_onearange (aranges, i);
	  if (ar != NULL)
	    {
	      Dwarf_Addr start;
	      Dwarf_Word length;
	      Dwarf_Off offset;
	      dwarf_getarangeinfo (ar, &start, &length, &offset);
	    }
	}
      dwarf_getarange_addr (aranges, 0x1000);
    }

  /* CFI from .debug_frame (pool-allocated, freed by dwarf_end).  */
  Dwarf_CFI *cfi = dwarf_getcfi (dbg);
  if (cfi != NULL)
    {
      Dwarf_Frame *frame = NULL;
      if (dwarf_cfi_addrframe (cfi, 0, &frame) == 0 && frame != NULL)
	{
	  Dwarf_Op *ops;
	  size_t nops;
	  dwarf_frame_cfa (frame, &ops, &nops);

	  Dwarf_Op reg_ops_mem[3];
	  Dwarf_Op *reg_ops;
	  size_t reg_nops;
	  for (int r = 0; r < 32; r++)
	    dwarf_frame_register (frame, r, reg_ops_mem, &reg_ops,
				 &reg_nops);

	  free (frame);
	}
    }

  /* CFI from .eh_frame via ELF.  */
  Dwarf_CFI *eh_cfi = dwarf_getcfi_elf (elf);
  if (eh_cfi != NULL)
    {
      Dwarf_Frame *frame = NULL;
      if (dwarf_cfi_addrframe (eh_cfi, 0, &frame) == 0 && frame != NULL)
	{
	  Dwarf_Op *ops;
	  size_t nops;
	  dwarf_frame_cfa (frame, &ops, &nops);
	  free (frame);
	}
      dwarf_cfi_end (eh_cfi);
    }

  /* Raw .debug_line iteration (independent of CU).  */
  Dwarf_Off off = 0;
  Dwarf_Off next_off;
  Dwarf_CU *raw_cu = NULL;
  Dwarf_Files *raw_files;
  size_t raw_nfiles;
  Dwarf_Lines *raw_lines;
  size_t raw_nlines;
  int line_count = 0;
  while (dwarf_next_lines (dbg, off, &next_off, &raw_cu,
			   &raw_files, &raw_nfiles,
			   &raw_lines, &raw_nlines) == 0
	 && line_count++ < 64)
    {
      for (size_t i = 0; i < raw_nlines && i < 256; i++)
	{
	  Dwarf_Line *l = dwarf_onesrcline (raw_lines, i);
	  if (l != NULL)
	    {
	      Dwarf_Addr a;
	      dwarf_lineaddr (l, &a);
	    }
	}
      off = next_off;
    }

  dwarf_end (dbg);
  elf_end (elf);
  free (buf);
  return 0;
}
