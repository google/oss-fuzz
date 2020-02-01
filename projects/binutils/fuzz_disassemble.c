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

static int objdump_sprintf (void *vf, const char *format, ...)
{
    SFILE *f = (SFILE *) vf;
    size_t n;
    va_list args;

    va_start (args, format);
    if (f->pos >= MAX_TEXT_SIZE){
        printf("buffer needs more space\n");
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

    if (Size < 10) {
        // 10 bytes for options
        return 0;
    }

    init_disassemble_info (&disasm_info, stdout, (fprintf_ftype) fprintf);
    disasm_info.fprintf_func = objdump_sprintf;
    disasm_info.print_address_func = generic_print_address;
    disasm_info.display_endian = disasm_info.endian = BFD_ENDIAN_LITTLE;
    disasm_info.buffer = (bfd_byte *) Data;
    disasm_info.buffer_vma = 0x1000;
    disasm_info.buffer_length = Size-10;
    disasm_info.insn_info_valid = 0;
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
            disasfunc(0x1000, &disasm_info);
            disassemble_free_target(&disasm_info);
        }
    }

    return 0;
}
