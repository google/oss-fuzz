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

#include "sysdep.h"
#include "bfd.h"
#include "dis-asm.h"
#include "disassemble.h"

#include <stdint.h>

#define MAX_TEXT_SIZE 256

typedef struct
{
    char *buffer;
    size_t pos;
} SFILE;

static int
fuzz_disasm_null_styled_printf (void *stream,
			       enum disassembler_style style,
			       const char *format, ...)
{
  return 0;
}

static int objdump_sprintf (void *vf, const char *format, ...)
{
    SFILE *f = (SFILE *) vf;
    size_t n;
    va_list args;

    va_start (args, format);
    if (f->pos >= MAX_TEXT_SIZE){
        printf("buffer needs more space\n");
        //reset
        f->pos=0;
        return 0;
    }
    n = vsnprintf (f->buffer + f->pos, MAX_TEXT_SIZE - f->pos, format, args);
    //vfprintf(stdout, format, args);
    va_end (args);
    f->pos += n;
    return n;
}


int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    char AssemblyText[MAX_TEXT_SIZE];
    struct disassemble_info disasm_info;
    SFILE s;

    if (Size < 10 || Size > 16394) {
        // 10 bytes for options
        // 16394 limit code to prevent timeouts
        return 0;
    }

    init_disassemble_info (&disasm_info, stdout, (fprintf_ftype) fprintf, fuzz_disasm_null_styled_printf);
    disasm_info.fprintf_func = objdump_sprintf;
    disasm_info.print_address_func = generic_print_address;
    disasm_info.display_endian = disasm_info.endian = BFD_ENDIAN_LITTLE;
    disasm_info.buffer = (bfd_byte *) Data;
    disasm_info.buffer_vma = 0x1000;
    disasm_info.buffer_length = Size-10;
    disasm_info.insn_info_valid = 0;
    disasm_info.created_styled_output = false;
    s.buffer = AssemblyText;
    s.pos = 0;
    disasm_info.stream = &s;
    disasm_info.bytes_per_line = 0;

    disasm_info.arch = Data[Size-1];
    disasm_info.mach = bfd_getl64(&Data[Size-9]);
    disasm_info.flavour = Data[Size-10];

    if (bfd_lookup_arch (disasm_info.arch, disasm_info.mach) != NULL) {
        disassembler_ftype disasfunc = disassembler(disasm_info.arch, 0, disasm_info.mach, NULL);
        if (disasfunc != NULL) {
            disassemble_init_for_target(&disasm_info);
            while (1) {
                s.pos = 0;
                int octets = disasfunc(disasm_info.buffer_vma, &disasm_info);
                if (octets < (int) disasm_info.octets_per_byte)
                    break;
                if (disasm_info.buffer_length <= (size_t) octets)
                    break;
                disasm_info.buffer += octets;
                disasm_info.buffer_vma += octets / disasm_info.octets_per_byte;
                disasm_info.buffer_length -= octets;
            }
            disassemble_free_target(&disasm_info);
        }
    }

    return 0;
}
