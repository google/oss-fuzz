#include "sysdep.h"
#include "bfd.h"

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

static int bufferToFile(char * name, const uint8_t *Data, size_t Size) {
    int fd = mkstemp(name);
    if (fd < 0) {
        printf("failed mkstemp, errno=%d\n", errno);
        return -2;
    }
    if (write (fd, Data, Size) != Size) {
        close(fd);
        return -3;
    }
    close(fd);
    return 0;
}

static int initialized = 0;
//TODO? part of fuzzing
char *target = NULL;

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    char tmpfilename[32];
    if (initialized == 0) {
        if (bfd_init () != BFD_INIT_MAGIC) {
            abort();
        }
        initialized = 1;
    }

    strncpy(tmpfilename, "/tmp/fuzz.bfd-XXXXXX", 31);
    if (bufferToFile(tmpfilename, Data, Size) < 0) {
        abort();
    }
    bfd *file = bfd_openr (tmpfilename, target);
    if (file == NULL)
    {
        return 0;
    }
    bfd_check_format (file, bfd_archive);
    //TODO loop over subfiles and more processing
    bfd_close (file);

    return 0;
}
