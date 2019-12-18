#include "sysdep.h"
#include "bfd.h"

#include <stdint.h>
#include <stdio.h>


static int bufferToFile(const char * name, const uint8_t *Data, size_t Size) {
    FILE * fd;
    if (remove(name) != 0) {
        if (errno != ENOENT) {
            printf("failed remove, errno=%d\n", errno);
            return -1;
        }
    }
    fd = fopen(name, "wb");
    if (fd == NULL) {
        printf("failed open, errno=%d\n", errno);
        return -2;
    }
    if (fwrite (Data, 1, Size, fd) != Size) {
        fclose(fd);
        return -3;
    }
    fclose(fd);
    return 0;
}

static int initialized = 0;
//TODO? part of fuzzing
char *target = NULL;

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (initialized == 0) {
        if (bfd_init () != BFD_INIT_MAGIC) {
            abort();
        }
        initialized = 1;
    }

    if (bufferToFile("/tmp/fuzz.bfd", Data, Size) < 0) {
        abort();
    }
    bfd *file = bfd_openr ("/tmp/fuzz.bfd", target);
    if (file == NULL)
    {
        return 0;
    }
    bfd_check_format (file, bfd_archive);
    //TODO loop over subfiles and more processing
    bfd_close (file);

    return 0;
}
