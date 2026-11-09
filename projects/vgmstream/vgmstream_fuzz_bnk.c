/* Copyright 2026 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************************
 *
 * vgmstream_fuzz_bnk.c — OSS-Fuzz harness for vgmstream's format dispatch.
 *
 * Despite the name, this harness is not BNK-specific. It writes the
 * fuzzer-supplied buffer to a tmp file in /dev/shm and calls
 * init_vgmstream(), which walks vgmstream's full demuxer dispatch table
 * (~447 formats in src/meta/*) until one matches. A single corpus
 * therefore exercises every parser in the library; the seed corpus and
 * dictionary are biased toward Sony BNK because that is the format with
 * the highest manually-verified bug density.
 *
 * Per-iteration cost is one mkstemp + one write + one init_vgmstream
 * call + one close + one unlink, all on tmpfs.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>

#include "vgmstream.h"

/* 8 MiB cap. vgmstream demuxers do their own bounds checks but we want
 * to keep per-iteration disk write small. Plenty of room for any
 * realistic header + a few sample frames. */
#define VGMSTREAM_FUZZ_MAX_SIZE  (8u * 1024u * 1024u)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > VGMSTREAM_FUZZ_MAX_SIZE) return 0;

    char path[] = "/dev/shm/vgmstream_fuzz_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) {
        /* /dev/shm should always be writable inside OSS-Fuzz runners; if
         * not, fall back to /tmp so we don't false-negative the corpus. */
        char path2[] = "/tmp/vgmstream_fuzz_XXXXXX";
        fd = mkstemp(path2);
        if (fd < 0) return 0;
        ssize_t w = write(fd, data, size);
        close(fd);
        if (w != (ssize_t)size) { unlink(path2); return 0; }
        VGMSTREAM *v = init_vgmstream(path2);
        if (v) close_vgmstream(v);
        unlink(path2);
        return 0;
    }

    ssize_t w = write(fd, data, size);
    close(fd);
    if (w != (ssize_t)size) {
        unlink(path);
        return 0;
    }

    VGMSTREAM *v = init_vgmstream(path);
    if (v) close_vgmstream(v);

    unlink(path);
    return 0;
}
