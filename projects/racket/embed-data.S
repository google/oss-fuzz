/* Boot files and the module bundle, embedded in the fuzz target so
   that it needs no files at run time. Assemble with
     -DPETITE_BOOT=<path> -DSCHEME_BOOT=<path> -DRACKET_BOOT=<path>
     -DFUZZ_MODULES=<path>
   (paths without quotes). */

#define STR1(x) #x
#define STR(x) STR1(x)

#define EMBED(name, path)                 \
        .global name;                     \
        .global name##_end;               \
        .balign 16;                       \
name:   .incbin STR(path);                \
name##_end: .byte 0

        .section .rodata
EMBED(fuzz_petite_boot, PETITE_BOOT)
EMBED(fuzz_scheme_boot, SCHEME_BOOT)
EMBED(fuzz_racket_boot, RACKET_BOOT)
EMBED(fuzz_modules, FUZZ_MODULES)

        .section .note.GNU-stack,"",%progbits
