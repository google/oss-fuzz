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
 */

/*
 * OSS-Fuzz harness for ncompress decompression (.Z / LZW).
 *
 * Feeds arbitrary bytes into decompress() as if they were a .Z stream and
 * discards the output. This is the untrusted-input parser: it reads a 3-byte
 * header (magic + maxbits/block_mode flags) then LZW-decodes the remainder,
 * unwinding code chains backwards through the de_stack region of htab[].
 *
 * decompress() is file-descriptor based, so the input is handed over through
 * an in-memory fd (memfd_create) and output is sent to /dev/null.
 *
 * ncompress's functions (decompress, read_error, ...) are `static`, and the
 * whole program lives in one file, so the harness #includes compress.c with
 * its main() renamed out of the way. This needs no change to upstream source.
 *
 * ncompress signals corrupt input by calling exit(1) (via abort_compress /
 * read_error / write_error). To keep fuzzing in-process and coverage-guided,
 * exit() is wrapped with a guarded longjmp trampoline (see __wrap_exit below):
 * a benign exit from the target returns cleanly, while genuine sanitizer
 * crashes (which terminate via abort/_exit, not exit) are still reported.
 *
 * Build (OSS-Fuzz): compile this file with -Dmain=ncompress_cli_main and link
 * against $LIB_FUZZING_ENGINE, with -Wl,--wrap=exit.
 */

#define _GNU_SOURCE
#include <setjmp.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

/* Pull in the whole program; its main() is renamed via -Dmain=... at build
 * time so it does not collide with the fuzzing engine's entry point. This
 * gives us the static decompress() and the ifname global. */
#include "compress.c"

/* --wrap=exit plumbing. __real_exit is the genuine libc exit; __wrap_exit
 * receives every exit() call from the linked objects. */
extern void __real_exit(int status) __attribute__((noreturn));

static jmp_buf g_exit_jb;
static volatile int g_in_target = 0;

void __wrap_exit(int status)
{
    if (g_in_target) {
        g_in_target = 0;
        longjmp(g_exit_jb, 1);     /* unwind back into TestOneInput */
    }
    __real_exit(status);           /* driver/sanitizer shutdown: real exit */
}

static int g_devnull = -1;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (g_devnull < 0)
        g_devnull = open("/dev/null", O_WRONLY | O_CLOEXEC);

    int fin = memfd_create("ncompress_fuzz_in", MFD_CLOEXEC);
    if (fin < 0)
        return 0;

    if (size) {
        if (write(fin, data, size) != (ssize_t)size) { close(fin); return 0; }
    }
    if (lseek(fin, 0, SEEK_SET) != 0) { close(fin); return 0; }

    /* Error messages read ifname[0]; keep it a valid empty string. */
    ifname = (char *)"";

    g_in_target = 1;
    if (setjmp(g_exit_jb) == 0)
        decompress(fin, g_devnull >= 0 ? g_devnull : fin);
    g_in_target = 0;

    close(fin);
    return 0;
}
