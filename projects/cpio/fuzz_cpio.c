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
 * OSS-Fuzz harness for GNU cpio's copy-in (archive extraction) parser.
 *
 * Feeds arbitrary bytes into process_copy_in() as if they were an archive read
 * by `cpio -i`. This is the untrusted-input path: cpio auto-detects the format
 * (old binary / old ASCII / new ASCII / CRC / tar / ustar) and parses every
 * header, filename, and the symlink/link bookkeeping.
 *
 * - Input is handed to cpio through an in-memory fd (memfd_create), assigned to
 *   the global `archive_des` that its buffered tape reader pulls from.
 * - table_flag (list mode, `-t`) is set so the parser reads and discards file
 *   bodies and prints names but performs NO filesystem mutation (no files,
 *   devices, dirs, or symlinks are created). Only the header/name parsers run.
 * - cpio signals malformed input by calling error(status, ...), which is hit on
 *   essentially every truncated input. glibc's error() calls exit() INTERNALLY
 *   (inside libc), so -Wl,--wrap=exit cannot intercept it; instead this file
 *   defines its own error()/error_at_line() (the executable's strong symbols
 *   preempt libc's) that longjmp back to the harness on a fatal diagnostic
 *   (status != 0) and simply return on a warning (status == 0), matching glibc
 *   semantics. -Wl,--wrap=exit additionally catches the few bare exit() calls in
 *   cpio's own objects. Genuine sanitizer crashes terminate through abort()/raw
 *   syscalls, which are NOT routed through libc exit(), so they are still
 *   reported.
 *
 * The harness is compiled as an extra src/ translation unit (same include flags
 * as copyin.c) and linked against cpio's own objects minus main.o, plus
 * lib/libpax.a and gnu/libgnu.a. No change to upstream cpio is required.
 */

#include <system.h>

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "filetypes.h"
#include "cpiohdr.h"
#include "dstring.h"
#include "extern.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

static jmp_buf g_exit_jb;
static volatile int g_in_target = 0;

/* cpio reports malformed input via error(status, ...)/error_at_line(...), which
 * call exit() INTERNALLY (inside libc or gnulib), so -Wl,--wrap=exit does not
 * see it. Intercept the functions themselves with -Wl,--wrap=error (and
 * error_at_line): on a fatal diagnostic (status != 0) unwind back to the
 * harness; on a warning (status == 0) return, exactly as the real error() does.
 * Using --wrap (rather than defining error() outright) avoids a multiple-
 * definition clash when gnulib's own error module is linked in. */
void
__wrap_error (int status, int errnum, const char *format, ...)
{
  (void) errnum;
  (void) format;
  if (status != 0)
    {
      if (g_in_target)
        {
          g_in_target = 0;
          longjmp (g_exit_jb, 1);
        }
      _exit (status);             /* outside a fuzz call: terminate for real */
    }
  /* status == 0: non-fatal warning, cpio continues. */
}

void
__wrap_error_at_line (int status, int errnum, const char *fname,
                      unsigned int lineno, const char *format, ...)
{
  (void) errnum;
  (void) fname;
  (void) lineno;
  (void) format;
  if (status != 0)
    {
      if (g_in_target)
        {
          g_in_target = 0;
          longjmp (g_exit_jb, 1);
        }
      _exit (status);
    }
}

/* Allocation cap. cpio sizes some buffers (e.g. the entry-name dstring) directly
 * from attacker-controlled header fields (namesize), so a crafted header can make
 * it request gigabytes -> OOM, and the request's result is abandoned by the
 * error-path longjmp. Intercept gnulib's x-allocators (via -Wl,--wrap=...) and
 * reject an implausibly large request as malformed input (longjmp back) BEFORE
 * any huge allocation happens. 16 MiB is far above any legitimate cpio metadata
 * allocation while keeping the fuzzer's RSS bounded. */
#define FUZZ_ALLOC_CAP (16UL * 1024 * 1024)

/* Per-iteration allocation tracking. cpio's error path is driven by error() ->
 * longjmp (below), which abandons whatever cpio allocated for the current
 * archive (chiefly the entry-name buffer grown by cpio_realloc_c_name). cpio is
 * a short-lived CLI and never frees these itself, so keeping the fuzzer process
 * alive would accumulate them until OOM. We record every gnulib x-allocation
 * made while inside process_copy_in() and free them after each input. This is
 * safe because the harness runs in table (list) mode with verbose off, where
 * cpio creates no persistent buffers and frees nothing during the call, so the
 * tracked pointers are exactly the abandoned ones. (Allocations made during
 * one-time init run with g_in_target == 0 and are intentionally not tracked.) */
static void **g_track;
static size_t g_track_n, g_track_cap;

static void
track_add (void *p)
{
  if (!p || !g_in_target)
    return;
  if (g_track_n == g_track_cap)
    {
      size_t nc = g_track_cap ? g_track_cap * 2 : 128;
      void **np = (void **) realloc (g_track, nc * sizeof (void *));
      if (!np)
        return;                 /* best-effort: drop tracking on OOM */
      g_track = np;
      g_track_cap = nc;
    }
  g_track[g_track_n++] = p;
}

static void
track_del (void *p)
{
  if (!p)
    return;
  for (size_t i = g_track_n; i-- > 0;)
    if (g_track[i] == p)
      {
        g_track[i] = g_track[--g_track_n];
        return;
      }
}

/* cpio frees through gnulib's rpl_free (free is #defined to it). Wrap it so that
 * when cpio frees one of our tracked buffers itself, we drop it from the tracker
 * and never double-free it at track_free_all() time. */
extern void __real_rpl_free (void *p);

void
__wrap_rpl_free (void *p)
{
  track_del (p);
  __real_rpl_free (p);
}

static void
track_free_all (void)
{
  for (size_t i = 0; i < g_track_n; i++)
    __real_rpl_free (g_track[i]);
  g_track_n = 0;
}

static void
reject_if_oversized (size_t nmemb, size_t size)
{
  size_t total = nmemb * size;
  if (size != 0 && total / size != nmemb)   /* multiplication overflowed */
    total = (size_t) -1;
  if (total > FUZZ_ALLOC_CAP && g_in_target)
    {
      g_in_target = 0;
      longjmp (g_exit_jb, 1);
    }
}

extern void *__real_xmalloc (size_t s);
extern void *__real_xrealloc (void *p, size_t s);
extern void *__real_xcalloc (size_t n, size_t s);
extern void *__real_xreallocarray (void *p, size_t n, size_t s);
extern void *__real_x2realloc (void *p, size_t *ps);
extern void *__real_x2nrealloc (void *p, size_t *pn, size_t s);

void *__wrap_xmalloc (size_t s)
{ reject_if_oversized (1, s); void *q = __real_xmalloc (s); track_add (q); return q; }

void *__wrap_xrealloc (void *p, size_t s)
{ reject_if_oversized (1, s); track_del (p); void *q = __real_xrealloc (p, s); track_add (q); return q; }

void *__wrap_xcalloc (size_t n, size_t s)
{ reject_if_oversized (n, s); void *q = __real_xcalloc (n, s); track_add (q); return q; }

void *__wrap_xreallocarray (void *p, size_t n, size_t s)
{ reject_if_oversized (n, s); track_del (p); void *q = __real_xreallocarray (p, n, s); track_add (q); return q; }

/* The doubling allocators are what cpio uses to grow the entry-name buffer from
 * the header's namesize (cpio_realloc_c_name -> x2realloc, util.c). They take the
 * current size by pointer and grow it ~1.5x, so cap by the PROJECTED next size.
 * These intra-cpio calls cross the object boundary, so --wrap catches them
 * (unlike the xreallocarray call made internally by gnulib). */
void *__wrap_x2realloc (void *p, size_t *ps)
{
  size_t cur = *ps;
  size_t next = cur + (cur >> 1) + 1;
  if ((next < cur || next > FUZZ_ALLOC_CAP) && g_in_target)
    {
      g_in_target = 0;
      longjmp (g_exit_jb, 1);
    }
  track_del (p);
  void *q = __real_x2realloc (p, ps);
  track_add (q);
  return q;
}

void *__wrap_x2nrealloc (void *p, size_t *pn, size_t s)
{
  size_t cur = *pn;
  size_t next = cur + (cur >> 1) + 1;
  reject_if_oversized (next, s);
  track_del (p);
  void *q = __real_x2nrealloc (p, pn, s);
  track_add (q);
  return q;
}

/* --wrap=exit catches the few bare exit() calls in cpio's own objects. */
extern void __real_exit (int status) __attribute__ ((noreturn));

void
__wrap_exit (int status)
{
  if (g_in_target)
    {
      g_in_target = 0;
      longjmp (g_exit_jb, 1);     /* unwind back into TestOneInput */
    }
  __real_exit (status);           /* driver/sanitizer shutdown: real exit */
}

static int g_initialized = 0;

static void
harness_init (void)
{
  /* Table mode prints each entry's name via list_file(); send it to /dev/null
   * so the listing does not dominate run time. libFuzzer logs to stderr. */
  int devnull = open ("/dev/null", O_WRONLY | O_CLOEXEC);
  if (devnull >= 0)
    {
      dup2 (devnull, STDOUT_FILENO);
      close (devnull);
    }

  io_block_size = DISK_IO_BLOCK_SIZE;
  copy_function = process_copy_in;
  initialize_buffers ();           /* allocates input_buffer / output_buffer */
  xstat = lstat;

  /* List-only: parse headers, no filesystem side effects, minimal chatter. */
  table_flag = 1;
  quiet_flag = 1;
  verbose_flag = 0;
  only_verify_crc_flag = 0;
  to_stdout_option = false;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (!g_initialized)
    {
      harness_init ();
      g_initialized = 1;
    }

  int fd = memfd_create ("cpio_fuzz_in", MFD_CLOEXEC);
  if (fd < 0)
    return 0;

  if (size && write (fd, data, size) != (ssize_t) size)
    {
      close (fd);
      return 0;
    }
  if (lseek (fd, 0, SEEK_SET) != 0)
    {
      close (fd);
      return 0;
    }

  /* Reset the per-archive parser state each iteration. */
  archive_des = fd;
  archive_format = arf_unknown;    /* force format auto-detection */
  crc_i_flag = 0;
  in_buff = input_buffer;
  input_size = 0;
  input_bytes = 0;

  g_in_target = 1;
  if (setjmp (g_exit_jb) == 0)
    process_copy_in ();
  g_in_target = 0;

  /* Free whatever cpio allocated for this archive and abandoned on the error
   * path, so the fuzzer's RSS stays flat across iterations. */
  track_free_all ();

  close (fd);
  return 0;
}
