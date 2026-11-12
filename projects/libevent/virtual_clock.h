/* Copyright 2026 Google LLC
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

/*
 * Virtual time for libevent fuzzers.
 *
 * libevent reads its timer clock with clock_gettime(CLOCK_MONOTONIC_COARSE)
 * (evutil_time.c, unless EVENT_BASE_FLAG_PRECISE_TIMER is set). This header
 * replaces clock_gettime() for that one clock id with a clock that stands
 * still until the harness advances it. Every other clock id, including the
 * ones libFuzzer and the sanitizers use for their own timeouts, still goes
 * to the kernel.
 *
 * With the real clock, two timers with the same duration get the same or
 * different deadlines depending on whether a clock tick happened between
 * them, so the order they fire in, and whether an input crashes, changed
 * from run to run. With this clock every deadline is a pure function of the
 * input:
 *  - vclock_reset() puts the clock back to the same start value; call it at
 *    the start of every input, before event_base_new();
 *  - vclock_tick() moves the clock forward to the earliest pending deadline
 *    and runs the loop, so every timer due at that instant fires, in
 *    libevent's own order, exactly as if that much real time had passed.
 * Timers never fire because the input happened to run slowly.
 *
 * libevent also reads the wall clock through gettimeofday(): every uncached
 * clock read resyncs base->tv_clock_diff (CLOCK_SYNC_INTERVAL is -1), and
 * event_base_gettimeofday_cached() feeds the token-bucket rate limiter's
 * tick counter (bufferevent_ratelim.c). gettimeofday() is therefore replaced
 * too, with a wall clock that moves in lockstep with the virtual monotonic
 * clock, so the number of rate-limit ticks that pass is a function of the
 * input as well.
 *
 * Include this from exactly one translation unit per fuzzer binary.
 */

#ifndef LIBEVENT_FUZZ_VIRTUAL_CLOCK_H
#define LIBEVENT_FUZZ_VIRTUAL_CLOCK_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

extern "C" {
#include "event2/event.h"
#include "event2/util.h"
}

#if defined(__has_feature)
#if __has_feature(memory_sanitizer)
#include <sanitizer/msan_interface.h>
#define VCLOCK_UNPOISON(p, n) __msan_unpoison((p), (n))
#endif
#endif
#ifndef VCLOCK_UNPOISON
#define VCLOCK_UNPOISON(p, n) ((void)0)
#endif

static struct timespec g_vclock;
static unsigned long g_vclock_reads;

extern "C" int clock_gettime(clockid_t id, struct timespec *ts) noexcept {
  if (id == CLOCK_MONOTONIC_COARSE) {
    *ts = g_vclock;
    g_vclock_reads++;
    return 0;
  }
  int r = (int)syscall(SYS_clock_gettime, id, ts);
  if (r == 0) VCLOCK_UNPOISON(ts, sizeof(*ts));
  return r;
}

#define VCLOCK_MONO_START 1000000
#define VCLOCK_WALL_START 1700000000 /* 2023-11-14, any fixed value works */

/* The wall clock: a fixed start date plus the virtual time elapsed. */
extern "C" int gettimeofday(struct timeval *tv, void *tz) noexcept {
  if (tv) {
    tv->tv_sec = VCLOCK_WALL_START + (g_vclock.tv_sec - VCLOCK_MONO_START);
    tv->tv_usec = g_vclock.tv_nsec / 1000;
  }
  if (tz) memset(tz, 0, sizeof(struct timezone));
  return 0;
}

static void vclock_reset(void) {
  g_vclock.tv_sec = VCLOCK_MONO_START;
  g_vclock.tv_nsec = 0;
}

/* Time passes by exactly 'tv' (whether or not a timer is due then), and the
 * loop runs so every timer due by then fires. */
static void vclock_advance(struct event_base *base, const struct timeval *tv) {
  long long ns = (long long)g_vclock.tv_nsec + tv->tv_usec * 1000LL;
  g_vclock.tv_sec += tv->tv_sec + ns / 1000000000LL;
  g_vclock.tv_nsec = ns % 1000000000LL;
  event_base_loop(base, EVLOOP_NONBLOCK);
}

/* Call once after creating the first event_base: stop if libevent is not
 * actually reading the virtual clock (e.g. it switched clock source), since
 * the harness would then silently lose its determinism. */
static void vclock_check_in_use(void) {
  if (g_vclock_reads == 0) {
    fprintf(stderr, "virtual_clock.h: libevent does not read "
                    "CLOCK_MONOTONIC_COARSE; the virtual clock has no "
                    "effect\n");
    abort();
  }
}

struct vclock_next {
  const struct event *skip;
  bool found;
  struct timeval tv;
};

static int vclock_pick(const struct event_base *base, const struct event *ev,
                       void *arg) {
  struct vclock_next *n = (struct vclock_next *)arg;
  struct timeval tv;
  if (ev == n->skip || !event_pending(ev, EV_TIMEOUT, &tv)) return 0;
  if (!n->found || evutil_timercmp(&tv, &n->tv, <)) {
    n->found = true;
    n->tv = tv;
  }
  return 0;
}

static void vclock_noop_cb(evutil_socket_t fd, short what, void *arg) {}

/* Time passes until the earliest pending deadline is reached. */
static void vclock_tick(struct event_base *base) {
  /* event_pending() reports deadlines on the wall clock (monotonic deadline
   * + an offset libevent takes from gettimeofday()). A reference timer due
   * exactly 1 s from now, read in the same pass, turns them back into
   * offsets from the virtual clock and cancels that offset out. */
  struct timeval one = {1, 0};
  struct timeval ref_tv;
  struct event *ref = evtimer_new(base, vclock_noop_cb, NULL);
  if (!ref) return;
  evtimer_add(ref, &one);
  event_pending(ref, EV_TIMEOUT, &ref_tv);
  struct vclock_next n = {ref, false, {0, 0}};
  event_base_foreach_event(base, vclock_pick, &n);
  event_free(ref);
  if (n.found) {
    struct timeval delta;
    evutil_timersub(&n.tv, &ref_tv, &delta);
    evutil_timeradd(&delta, &one, &delta);
    if (delta.tv_sec > 0 || (delta.tv_sec == 0 && delta.tv_usec > 0)) {
      long long ns = (long long)g_vclock.tv_nsec + delta.tv_usec * 1000LL;
      g_vclock.tv_sec += delta.tv_sec + ns / 1000000000LL;
      g_vclock.tv_nsec = ns % 1000000000LL;
    }
  }
  event_base_loop(base, EVLOOP_NONBLOCK);
}

#endif /* LIBEVENT_FUZZ_VIRTUAL_CLOCK_H */
