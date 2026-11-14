/*
   Copyright 2026 Google LLC

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

/* libFuzzer driver for Racket CS.

   Boots Racket CS once, loads "safe-eval.rkt", and calls one of its
   `fuzz-*` entry points on each input. An entry point returns 0 for
   every expected outcome, and for a bug either 1 or a description,
   which becomes a failed assertion here.

   Compile-time settings (all strings):
     FUZZ_ENTRY     entry point name, such as "fuzz-eval"
   and either
     FUZZ_EMBEDDED  defined: boot files and modules come from
                    "embed-data.S", and no files are needed at run time
   or
     FUZZ_MODULE    absolute path of "safe-eval.rkt"
     BOOT_DIR       directory holding petite.boot, scheme.boot, racket.boot
     COLLECTS_DIR   the "collects" directory
     CONFIG_DIR     the "etc" directory
   and optionally
     FUZZ_ADDON_DIR   the addon directory, so that Racket does not look
                    for the home directory

   With RACKET_COVERAGE_COUNTERS defined (and a Racket CS built with it
   and with PLT_CS_COVERAGE_COUNTERS set), Scheme code also reports
   coverage: the Chez Scheme counters are registered with libFuzzer
   like clang's inline 8-bit counters. Code that a fuzzed program
   compiles gets no counters, since counters placed by hashing the
   program's own code would reward new programs, not new behavior of
   Racket. */

#ifndef _GNU_SOURCE
# define _GNU_SOURCE /* for REG_RIP and dladdr */
#endif
#include <assert.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "chezscheme.h"
#include "racketcs.h"

#ifndef __has_feature
# define __has_feature(x) 0
#endif
#if defined(__SANITIZE_ADDRESS__) || __has_feature(address_sanitizer)
# include <sanitizer/lsan_interface.h>
# define FUZZ_LSAN_DISABLE() __lsan_disable()
# define FUZZ_LSAN_ENABLE() __lsan_enable()
#else
# define FUZZ_LSAN_DISABLE() (void)0
# define FUZZ_LSAN_ENABLE() (void)0
#endif

#ifndef FUZZ_ENTRY
# define FUZZ_ENTRY "fuzz-eval"
#endif

static ptr entry_proc;

#ifdef FUZZ_EMBEDDED
extern char fuzz_petite_boot[], fuzz_petite_boot_end[];
extern char fuzz_scheme_boot[], fuzz_scheme_boot_end[];
extern char fuzz_racket_boot[], fuzz_racket_boot_end[];
extern char fuzz_modules[], fuzz_modules_end[];
#endif

/* Chez Scheme turns every memory fault into an "invalid memory
   reference" exception, and every exception that the harness counts
   as a bug ends in `report_bug` below, with no C stack trace of its
   own. For a fault in C code,
   the sanitizer's report and stack trace say much more, so send those
   faults to the handler that was in place before booting. A fault in
   Scheme code, which is outside any shared object or the executable,
   still goes to Chez Scheme, since the sanitizer cannot walk Scheme
   frames; "safe-eval.rkt" then prints the Racket context and describes
   the bug by where in Racket it happened. Racket does
   not rely on these signals in normal operation. */
static struct sigaction sanitizer_segv, sanitizer_bus, chez_segv, chez_bus;

#if defined(__linux__) && (defined(__x86_64__) || defined(__aarch64__))
# include <dlfcn.h>
# include <ucontext.h>

static int fault_in_c_code(void *data)
{
  ucontext_t *uc = (ucontext_t *)data;
  Dl_info info;
# if defined(__x86_64__)
  void *pc = (void *)uc->uc_mcontext.gregs[REG_RIP];
# else
  void *pc = (void *)uc->uc_mcontext.pc;
# endif
  return dladdr(pc, &info) != 0;
}

static void call_handler(struct sigaction *sa, int sig, siginfo_t *si, void *data)
{
  if (sa->sa_flags & SA_SIGINFO)
    sa->sa_sigaction(sig, si, data);
  else if ((sa->sa_handler != SIG_DFL) && (sa->sa_handler != SIG_IGN))
    sa->sa_handler(sig);
  else {
    /* returning re-runs the faulting instruction, now with the
       default action */
    signal(sig, SIG_DFL);
  }
}

static void handle_fault(int sig, siginfo_t *si, void *data)
{
  int is_segv = (sig == SIGSEGV);
  if (fault_in_c_code(data))
    call_handler(is_segv ? &sanitizer_segv : &sanitizer_bus, sig, si, data);
  else
    call_handler(is_segv ? &chez_segv : &chez_bus, sig, si, data);
}

static void split_fault_handlers(void)
{
  struct sigaction act;

  sigaction(SIGSEGV, NULL, &chez_segv);
  sigaction(SIGBUS, NULL, &chez_bus);

  act = chez_segv;
  act.sa_flags |= SA_SIGINFO | (sanitizer_segv.sa_flags & SA_ONSTACK);
  act.sa_sigaction = handle_fault;
  sigaction(SIGSEGV, &act, NULL);
  sigaction(SIGBUS, &act, NULL);
}
#else
static void split_fault_handlers(void) { }
#endif


#ifdef RACKET_COVERAGE_COUNTERS
void __sanitizer_cov_8bit_counters_init(uint8_t *start, uint8_t *stop);
void __sanitizer_cov_pcs_init(const uintptr_t *pcs_beg, const uintptr_t *pcs_end);

/* libFuzzer wants a PC table entry, a (PC, flags) pair, for each
   counter; the PCs only need to be distinct. */
static void register_scheme_counters(void)
{
  iptr len;
  uint8_t *counters = Scoverage_counters(&len);
  uintptr_t *pcs;
  iptr i;

  if (!counters) return;

  pcs = malloc(2 * len * sizeof(uintptr_t));
  for (i = 0; i < len; i++) {
    pcs[2 * i] = (uintptr_t)(counters + i);
    pcs[2 * i + 1] = 0;
  }

  __sanitizer_cov_8bit_counters_init(counters, counters + len);
  __sanitizer_cov_pcs_init(pcs, pcs + 2 * len);
}
#endif

static int initialized = 0;

/* An error while booting or loading the harness ends the process with
   `exit`, often with status 0, which would look like a passing run. */
static void check_initialized(void)
{
  /* not a property: Racket failed to boot or to load the harness */
  if (!initialized) {
    fprintf(stderr, "racket-fuzz: initialization failed\n");
    abort();
  }
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
  racket_boot_arguments_t ba;

  atexit(check_initialized);

  memset(&ba, 0, sizeof(ba));
#ifdef FUZZ_EMBEDDED
  ba.boot1_data = fuzz_petite_boot;
  ba.boot1_len = fuzz_petite_boot_end - fuzz_petite_boot;
  ba.boot2_data = fuzz_scheme_boot;
  ba.boot2_len = fuzz_scheme_boot_end - fuzz_scheme_boot;
  ba.boot3_data = fuzz_racket_boot;
  ba.boot3_len = fuzz_racket_boot_end - fuzz_racket_boot;
  ba.collects_dir = "";
  ba.config_dir = NULL;
#else
  ba.boot1_path = BOOT_DIR "/petite.boot";
  ba.boot2_path = BOOT_DIR "/scheme.boot";
  ba.boot3_path = BOOT_DIR "/racket.boot";
  /* A list of paths, each ending in NUL, with an extra NUL at the end;
     `parse_coldirs` in "boot.c" reads past a single NUL. */
  ba.collects_dir = COLLECTS_DIR "\0";
  ba.config_dir = CONFIG_DIR;
#endif
  ba.exec_file = "racket-fuzz";
  ba.exit_after = 0;
#ifdef FUZZ_ADDON_DIR
  /* Naming the addon directory keeps Racket from finding it through
     the home directory, which looks in "/etc/passwd" when HOME is not
     set; "-n" is what a NULL `argv` would mean */
  {
    static char *args[] = { "-A", FUZZ_ADDON_DIR, "-n", NULL };
    ba.argc = 3;
    ba.argv = args;
  }
#endif

  /* Racket keeps what it allocates while booting until the process
     exits, often referenced only from the Scheme heap, which
     LeakSanitizer does not scan; so don't report those as leaks.
     Leaks from running an input are still reported. */
  FUZZ_LSAN_DISABLE();

  sigaction(SIGSEGV, NULL, &sanitizer_segv);
  sigaction(SIGBUS, NULL, &sanitizer_bus);

  racket_boot(&ba);

  split_fault_handlers();

#ifdef RACKET_COVERAGE_COUNTERS
  register_scheme_counters();
#endif

#ifdef FUZZ_EMBEDDED
  racket_embedded_load_bytes(fuzz_modules, fuzz_modules_end - fuzz_modules, 0);
#endif

  {
#ifdef FUZZ_EMBEDDED
    /* "embed-modules.rkt" declares the module as 'fuzz:safe-eval */
    ptr mod_path = Scons(Sstring_to_symbol("quote"),
                         Scons(Sstring_to_symbol("fuzz:safe-eval"), Snil));
#else
    ptr mod_path = Scons(Sstring_to_symbol("file"),
                         Scons(Sstring(FUZZ_MODULE), Snil));
#endif
    ptr vals = racket_dynamic_require(mod_path, Sstring_to_symbol(FUZZ_ENTRY));
    entry_proc = Scar(vals);
    Slock_object(entry_proc);
  }

  FUZZ_LSAN_ENABLE();

  initialized = 1;

  return 0;
}

/* Reports a bug found by "safe-eval.rkt" as a failed assertion, which
   prints the description and aborts. A fuzzing service groups crashes
   by an assertion's message, so bugs with different descriptions are
   reported separately, although they all end here. */
static void report_bug(const char *what)
{
  __assert_fail(what, "safe-eval.rkt", 0, FUZZ_ENTRY);
}

static void check_result(ptr vals)
{
  ptr r;

  if (!Spairp(vals))
    report_bug("no result");
  r = Scar(vals);
  if (Sstringp(r)) {
    char buf[256];
    iptr i, len = Sstring_length(r);
    if (len > (iptr)sizeof(buf) - 1)
      len = sizeof(buf) - 1;
    for (i = 0; i < len; i++) {
      string_char c = Sstring_ref(r, i);
      buf[i] = ((c >= 32) && (c < 127)) ? (char)c : '?';
    }
    buf[len] = 0;
    report_bug(buf);
  } else if (!Sfixnump(r) || (Sfixnum_value(r) != 0)) {
    static const char *properties[] = {
      NULL,
      "print round trip failed",
      "exact number round trip failed",
      "inexact number round trip failed",
      "regexp-match and regexp-match-positions disagree",
      "fasl round trip failed",
      "fasl->s-exp raised a value that is not exn:fail",
      "heap check failed"
    };
    iptr n = Sfixnump(r) ? Sfixnum_value(r) : 0;
    if ((n > 0) && (n < (iptr)(sizeof(properties) / sizeof(properties[0]))))
      report_bug(properties[n]);
    else
      report_bug("wrong result");
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  ptr bstr = Smake_bytevector(size, 0);

  memcpy(Sbytevector_data(bstr), data, size);
  check_result(racket_apply(entry_proc, Scons(bstr, Snil)));

  return 0;
}
