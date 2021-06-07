/*
 * IPP fuzzing program for CUPS.
 *
 * Copyright © 2007-2021 by Apple Inc.
 * Copyright © 1997-2005 by Easy Software Products.
 *
 * Licensed under Apache License v2.0.  See the file "LICENSE" for more
 * information.
 */

/*
 * Include necessary headers...
 */

#include "file.h"
#include "string-private.h"
#include "ipp-private.h"
#ifdef _WIN32
#  include <io.h>
#else
#  include <unistd.h>
#  include <fcntl.h>
#endif /* _WIN32 */


/*
 * Local types...
 */

typedef struct _fuzzBuffer_t
{
    const uint8_t *Data;
    size_t Size;
    size_t Offset;
} fuzzBuffer_t;

size_t fuzz_read(fuzzBuffer_t *fb, uint8_t *out, size_t n) {
    if (fb->Offset + n > fb->Size) {
        fb->Offset = fb->Size;
        return 0;
    }
    memcpy(out, fb->Data + fb->Offset, n);
    fb->Offset += n;
    return n;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    fuzzBuffer_t fb;
    fb.Data = Data;
    fb.Size = Size;
    fb.Offset = 0;
    ipp_state_t state;

    ipp_t *request = ippNew();
    do
    {
      state = ippReadIO(&fb, (ipp_iocb_t)fuzz_read, 1, NULL, request);
    }
    while (state == IPP_STATE_ATTRIBUTE);

    cups_file_t *fp = cupsFileOpen("/dev/null", "w");

    ippSetState(request, IPP_STATE_IDLE);

    do
    {
      state = ippWriteIO(fp, (ipp_iocb_t)cupsFileWrite, 1, NULL, request);
    }
    while (state == IPP_STATE_ATTRIBUTE);

    cupsFileClose(fp);
    ippDelete(request);

    return (0);
}
