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
 * Fuzzer for socket-backed bufferevents (bufferevent_sock.c) and the
 * token-bucket rate limiter that sits in their read/write path
 * (bufferevent_ratelim.c).
 *
 * Threat model: a remote peer on a stream connection decides what bytes
 * arrive, how they are split into segments, when it stops reading and when
 * it half-closes or resets the connection. The application around the
 * bufferevent uses ordinary, valid configuration: watermarks, per-read and
 * per-write caps, and per-connection and/or group rate limits.
 *
 * The existing bufferevent_fuzzer creates its socket bufferevents with
 * fd == -1, so no byte ever moves through bufferevent_readcb() /
 * bufferevent_writecb() and the rate-limit buckets are never drained. This
 * harness gives the bufferevent one end of a real socketpair and plays the
 * peer on the other end.
 *
 * Input layout (consumed in this order):
 *   u8   opts        bit0 defer callbacks, bit1 per-connection rate limit,
 *                    bit2 group rate limit, bit3 read callback leaves data
 *                    in the input buffer, bit4 start by connecting to a
 *                    loopback listener instead of using a socketpair
 *   u16 x4           read rate, read burst, write rate, write burst
 *   then up to MAX_OPS operations: u8 opcode + operands (see the switch)
 *
 * Every input is self-contained, so a crash or hang reproduces from its
 * input alone in a fresh process and never depends on earlier inputs: each
 * input gets its own event_base and sockets, and time is virtual
 * (virtual_clock.h). The clock is reset for every input and only moves when
 * the input says so (operation 11), so rate-limit refills and the
 * bufferevent read/write timeouts happen at the same point every run.
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <vector>

#include <fuzzer/FuzzedDataProvider.h>

extern "C" {
#include "event2/buffer.h"
#include "event2/bufferevent.h"
#include "event2/event.h"
#include "event2/util.h"
}

#include "virtual_clock.h"

#define MAX_OPS 24
#define MAX_CHUNK 4096

static bool g_leave_data;

static void log_cb(int severity, const char *msg) {}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  event_set_log_callback(log_cb);
  /* Like any network program: a peer that went away must surface as a
   * write error, not kill the process. */
  signal(SIGPIPE, SIG_IGN);
  return 0;
}

static void read_cb(struct bufferevent *bev, void *ctx) {
  struct evbuffer *input = bufferevent_get_input(bev);
  size_t len = evbuffer_get_length(input);
  /* Either consume everything, or behave like a parser that is waiting for
   * more data and leaves half of it buffered. */
  evbuffer_drain(input, g_leave_data ? len / 2 : len);
}

static void write_cb(struct bufferevent *bev, void *ctx) {}

static void event_cb(struct bufferevent *bev, short what, void *ctx) {
  if (what & BEV_EVENT_ERROR) (void)EVUTIL_SOCKET_ERROR();
}

static void drain_fd(int fd) {
  char buf[4096];
  while (fd >= 0 && recv(fd, buf, sizeof(buf), MSG_DONTWAIT) > 0) {
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 10) return 0;
  FuzzedDataProvider fdp(data, size);

  uint8_t opts = fdp.ConsumeIntegral<uint8_t>();
  size_t read_rate = fdp.ConsumeIntegralInRange<uint16_t>(1, 8192);
  size_t read_burst = read_rate + fdp.ConsumeIntegralInRange<uint16_t>(0, 8192);
  size_t write_rate = fdp.ConsumeIntegralInRange<uint16_t>(1, 8192);
  size_t write_burst =
      write_rate + fdp.ConsumeIntegralInRange<uint16_t>(0, 8192);
  g_leave_data = (opts & 8) != 0;

  vclock_reset();
  struct event_base *base = event_base_new();
  if (!base) return 0;
  vclock_check_in_use();

  int peer = -1;   /* the remote end, driven by the fuzz input */
  int lfd = -1;    /* listening socket for the connect() variant */
  struct bufferevent *bev = NULL;
  int bev_opts = BEV_OPT_CLOSE_ON_FREE | ((opts & 1) ? BEV_OPT_DEFER_CALLBACKS : 0);

  if (opts & 16) {
    /* Outgoing connection made by the bufferevent itself. */
    struct sockaddr_in sin;
    socklen_t slen = sizeof(sin);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    lfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (lfd < 0 || bind(lfd, (struct sockaddr *)&sin, sizeof(sin)) != 0 ||
        listen(lfd, 4) != 0 ||
        getsockname(lfd, (struct sockaddr *)&sin, &slen) != 0) {
      if (lfd >= 0) close(lfd);
      event_base_free(base);
      return 0;
    }
    bev = bufferevent_socket_new(base, -1, bev_opts);
    if (bev) {
      bufferevent_setcb(bev, read_cb, write_cb, event_cb, NULL);
      bufferevent_socket_connect(bev, (struct sockaddr *)&sin, sizeof(sin));
      event_base_loop(base, EVLOOP_NONBLOCK);
      peer = accept4(lfd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
    }
  } else {
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0,
                   fds) != 0) {
      event_base_free(base);
      return 0;
    }
    peer = fds[1];
    bev = bufferevent_socket_new(base, fds[0], bev_opts);
    if (!bev) close(fds[0]);
  }

  struct ev_token_bucket_cfg *cfg = NULL;
  struct bufferevent_rate_limit_group *group = NULL;
  bool has_limit = false; /* a per-connection limit is installed */
  /* One millisecond per rate-limit tick (see operation 11). */
  const struct timeval tick = {0, 1000};

  if (!bev) goto cleanup;

  cfg = ev_token_bucket_cfg_new(read_rate, read_burst, write_rate, write_burst,
                                &tick);
  if (cfg && (opts & 2))
    has_limit = bufferevent_set_rate_limit(bev, cfg) == 0;
  if (cfg && (opts & 4)) {
    group = bufferevent_rate_limit_group_new(base, cfg);
    if (group) bufferevent_add_to_rate_limit_group(bev, group);
  }

  bufferevent_setcb(bev, read_cb, write_cb, event_cb, NULL);
  bufferevent_enable(bev, EV_READ | EV_WRITE);

  for (int i = 0; i < MAX_OPS && fdp.remaining_bytes() > 0; i++) {
    switch (fdp.ConsumeIntegralInRange<uint8_t>(0, 13)) {
      case 0: { /* peer sends a segment */
        std::vector<uint8_t> chunk = fdp.ConsumeBytes<uint8_t>(
            fdp.ConsumeIntegralInRange<uint16_t>(0, MAX_CHUNK));
        if (peer >= 0)
          send(peer, chunk.data(), chunk.size(), MSG_NOSIGNAL | MSG_DONTWAIT);
        break;
      }
      case 1: { /* application writes */
        std::vector<uint8_t> chunk = fdp.ConsumeBytes<uint8_t>(
            fdp.ConsumeIntegralInRange<uint16_t>(0, MAX_CHUNK));
        bufferevent_write(bev, chunk.data(), chunk.size());
        break;
      }
      case 2: /* peer reads what it was sent */
        drain_fd(peer);
        break;
      case 3: /* peer half-closes: EOF for the bufferevent */
        if (peer >= 0) shutdown(peer, SHUT_WR);
        break;
      case 4: /* peer goes away */
        if (peer >= 0) close(peer);
        peer = -1;
        break;
      case 5: {
        size_t lo = fdp.ConsumeIntegralInRange<uint16_t>(0, 2048);
        size_t hi = lo + fdp.ConsumeIntegralInRange<uint16_t>(0, 2048);
        bufferevent_setwatermark(
            bev, fdp.ConsumeBool() ? EV_READ : EV_WRITE, lo, hi);
        break;
      }
      case 6:
        bufferevent_set_max_single_read(
            bev, fdp.ConsumeIntegralInRange<uint16_t>(0, 4096));
        bufferevent_set_max_single_write(
            bev, fdp.ConsumeIntegralInRange<uint16_t>(0, 4096));
        (void)bufferevent_get_max_single_read(bev);
        (void)bufferevent_get_max_single_write(bev);
        break;
      case 7: {
        short ev = fdp.ConsumeBool() ? EV_READ : EV_WRITE;
        if (fdp.ConsumeBool())
          bufferevent_disable(bev, ev);
        else
          bufferevent_enable(bev, ev);
        break;
      }
      case 8:
        bufferevent_flush(bev, EV_READ | EV_WRITE,
                          fdp.ConsumeBool() ? BEV_FLUSH : BEV_FINISHED);
        break;
      case 9: /* the application charges extra bytes to the buckets */
        /* Only valid while a per-connection limit is installed. */
        if (has_limit) {
          bufferevent_decrement_read_limit(
              bev, fdp.ConsumeIntegralInRange<int16_t>(-4096, 4096));
          bufferevent_decrement_write_limit(
              bev, fdp.ConsumeIntegralInRange<int16_t>(-4096, 4096));
        }
        (void)bufferevent_get_read_limit(bev);
        (void)bufferevent_get_write_limit(bev);
        (void)bufferevent_get_max_to_read(bev);
        (void)bufferevent_get_max_to_write(bev);
        break;
      case 10:
        if (group) {
          ev_uint64_t rd, wr;
          bufferevent_rate_limit_group_decrement_read(
              group, fdp.ConsumeIntegralInRange<int16_t>(-4096, 4096));
          bufferevent_rate_limit_group_decrement_write(
              group, fdp.ConsumeIntegralInRange<int16_t>(-4096, 4096));
          bufferevent_rate_limit_group_set_min_share(
              group, fdp.ConsumeIntegralInRange<uint16_t>(0, 4096));
          (void)bufferevent_rate_limit_group_get_read_limit(group);
          (void)bufferevent_rate_limit_group_get_write_limit(group);
          bufferevent_rate_limit_group_get_totals(group, &rd, &wr);
          bufferevent_rate_limit_group_reset_totals(group);
        }
        break;
      case 11: /* time passes */
        if (fdp.ConsumeBool())
          /* exactly one rate-limit tick, so the buckets refill */
          vclock_advance(base, &tick);
        else
          /* until the next timer is due: a refill, or a read/write
           * timeout set with operation 13 */
          vclock_tick(base);
        break;
      case 12: /* drop / restore the rate limits */
        if (fdp.ConsumeBool()) {
          struct ev_token_bucket_cfg *c = fdp.ConsumeBool() ? cfg : NULL;
          if (bufferevent_set_rate_limit(bev, c) == 0) has_limit = c != NULL;
        } else if (group) {
          if (fdp.ConsumeBool())
            bufferevent_remove_from_rate_limit_group(bev);
          else
            bufferevent_add_to_rate_limit_group(bev, group);
        }
        break;
      case 13: {
        struct timeval tv = {30, 0};
        bool on = fdp.ConsumeBool();
        bufferevent_set_timeouts(bev, on ? &tv : NULL, on ? &tv : NULL);
        break;
      }
    }
    event_base_loop(base, EVLOOP_NONBLOCK);
  }

cleanup:
  if (bev) {
    if (group) bufferevent_remove_from_rate_limit_group(bev);
    bufferevent_free(bev);
  }
  /* Run the deferred finalizers before the limiter objects go away. */
  event_base_loop(base, EVLOOP_NONBLOCK);
  if (group) bufferevent_rate_limit_group_free(group);
  if (cfg) ev_token_bucket_cfg_free(cfg);
  if (peer >= 0) close(peer);
  if (lfd >= 0) close(lfd);
  event_base_free(base);
  return 0;
}
