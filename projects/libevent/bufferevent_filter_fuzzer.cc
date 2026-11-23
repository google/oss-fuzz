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
 * Fuzzer for filtering bufferevents (bufferevent_filter.c) stacked on a
 * socket bufferevent, and for the generic bufferevent machinery they share
 * (bufferevent.c: watermarks, flush modes, read/write timeouts, triggers,
 * fd replacement, freeing from inside a callback).
 *
 * Threat model: a remote peer on a stream connection controls the bytes
 * that arrive, how they are segmented, when it half-closes or goes away,
 * and how long it stays silent (timeouts). The application decodes the
 * stream with a filter - the way libevent's filters are used for framing,
 * compression or TLS - so the filter's decisions (BEV_OK / BEV_NEED_MORE /
 * BEV_ERROR, how much it produces) follow the attacker's bytes. The
 * application's own API calls are ordinary and valid.
 *
 * The existing bufferevent_fuzzer only creates filters with NULL (pass
 * through) filter functions over fd-less or paired bufferevents and never
 * flushes, times out, half-closes or replaces the fd, so the filter's
 * flush / EOF / inbuf-watermark paths and bufferevent's generic timeout
 * callbacks are never reached.
 *
 * The filter is a small streaming record codec: each record is a 1-byte
 * length L and L payload bytes; L == 0xff is a protocol error, as is a
 * truncated record at end of stream. Like a real decoder it emits partial
 * payloads up to the limit it is given. The output side packs application
 * data into records of a configurable size and emits an empty record when
 * the stream is finished.
 *
 * Time is virtual (virtual_clock.h): libevent's clock stands still and the
 * "tick" operation moves it forward to the earliest pending deadline, so
 * every timer due then fires, exactly as if that much time had passed.
 *
 * Every input is self-contained, so a crash reproduces from its input alone
 * in a fresh process and never depends on earlier inputs: the clock is
 * reset, the socketpair, event_base and bufferevents are created for each
 * input and destroyed at its end, and all harness globals are reset.
 *
 * Input layout (consumed in this order):
 *   u8  cfg   bit0 defer callbacks, bit1 stack a second filter,
 *             bit2 read callback leaves half the data buffered,
 *             bit3 free the bufferevent from the event callback on EOF or
 *             error, bits 4-7 output record size - 1
 *   then up to MAX_OPS operations: u8 opcode + operands (see the switch)
 */

#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <vector>

#include <fuzzer/FuzzedDataProvider.h>

#include "virtual_clock.h"

extern "C" {
#include "event2/buffer.h"
#include "event2/bufferevent.h"
#include "event2/bufferevent_compat.h" /* bufferevent_settimeout() */
#include "event2/event.h"
#include "event2/util.h"
}

#define MAX_OPS 48
#define MAX_CHUNK 2048

struct app_state {
  struct bufferevent *top; /* NULL once freed */
  bool leave_data;
  bool free_on_eof;
  size_t rec_size; /* payload bytes per output record */
};
static struct app_state g_app;

/* Per-layer codec state: payload bytes still expected from the record
 * currently being decoded. */
struct codec {
  struct app_state *app;
  size_t in_remaining;
  bool in_decode; /* decode_records() is running for this layer */
};
static struct codec g_codec[2];

static void log_cb(int severity, const char *msg) {}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  event_set_log_callback(log_cb);
  signal(SIGPIPE, SIG_IGN);
  return 0;
}

/* ---- the application's filter ----------------------------------------- */

/* Streaming decoder: like a real decompressor or TLS layer it emits as
 * much payload as the output limit allows and keeps its position inside
 * the current record, so it never stalls while input is available and the
 * consumer has room. */
static enum bufferevent_filter_result
decode_records_body(struct codec *c, struct evbuffer *src,
                    struct evbuffer *dst, ev_ssize_t lim,
                    enum bufferevent_flush_mode mode) {
  bool produced = false;
  while (evbuffer_get_length(src) > 0) {
    if (c->in_remaining == 0) {
      unsigned char len;
      evbuffer_remove(src, &len, 1);
      if (len == 0xff) return BEV_ERROR; /* malformed stream */
      c->in_remaining = len;
      produced = true;
      continue;
    }
    if (lim == 0) break;
    unsigned char buf[256];
    size_t n = c->in_remaining;
    if (n > evbuffer_get_length(src)) n = evbuffer_get_length(src);
    if (lim > 0 && (size_t)lim < n) n = (size_t)lim;
    evbuffer_remove(src, buf, n);
    for (size_t i = 0; i < n; i++) buf[i] ^= 0x5a;
    evbuffer_add(dst, buf, n);
    c->in_remaining -= n;
    if (lim > 0) lim -= (ev_ssize_t)n;
    produced = true;
  }
  /* A truncated record at end of stream is a protocol error. */
  if (mode == BEV_FINISHED && c->in_remaining > 0 &&
      evbuffer_get_length(src) == 0)
    return BEV_ERROR;
  return produced ? BEV_OK : BEV_NEED_MORE;
}

static enum bufferevent_filter_result
decode_records(struct evbuffer *src, struct evbuffer *dst, ev_ssize_t lim,
               enum bufferevent_flush_mode mode, void *ctx) {
  struct codec *c = (struct codec *)ctx;
  /* A filter is a sequential stream transform: libevent must not call it
   * again while the same call is still running (as it does when the
   * filter's own evbuffer_add(dst) triggers the inbuf watermark callback).
   * Real stateful filters such as zlib or framing codecs are corrupted by
   * that, so report it at the point it happens rather than waiting for
   * the corrupted state to cause a crash later. */
  if (c->in_decode) {
    fprintf(stderr, "libevent re-entered the input filter from inside "
                    "itself (bufferevent_filtered_inbuf_cb)\n");
    abort();
  }
  c->in_decode = true;
  enum bufferevent_filter_result r =
      decode_records_body(c, src, dst, lim, mode);
  c->in_decode = false;
  return r;
}

static enum bufferevent_filter_result
encode_records(struct evbuffer *src, struct evbuffer *dst, ev_ssize_t lim,
               enum bufferevent_flush_mode mode, void *ctx) {
  struct codec *c = (struct codec *)ctx;
  bool produced = false;
  while (evbuffer_get_length(src) > 0) {
    size_t n = evbuffer_get_length(src);
    if (n > c->app->rec_size) n = c->app->rec_size;
    if (lim >= 0) {
      if (lim < 2) break;
      if ((size_t)lim < n + 1) n = (size_t)lim - 1;
    }
    unsigned char buf[256];
    buf[0] = (unsigned char)n;
    evbuffer_remove(src, buf + 1, n);
    for (size_t i = 1; i <= n; i++) buf[i] ^= 0x5a;
    evbuffer_add(dst, buf, n + 1);
    if (lim >= 0) lim -= (ev_ssize_t)(n + 1);
    produced = true;
  }
  if (mode == BEV_FINISHED && evbuffer_get_length(src) == 0) {
    unsigned char end = 0;
    evbuffer_add(dst, &end, 1);
    produced = true;
  }
  return produced ? BEV_OK : BEV_NEED_MORE;
}

/* ---- the application's callbacks --------------------------------------- */

static void read_cb(struct bufferevent *bev, void *ctx) {
  struct app_state *app = (struct app_state *)ctx;
  struct evbuffer *in = bufferevent_get_input(bev);
  size_t len = evbuffer_get_length(in);
  /* Either consume everything, or behave like a parser that is waiting
   * for more data and leaves part of it buffered (but always makes some
   * progress, so a read high-watermark is eventually drained). */
  size_t take = app->leave_data ? (len + 1) / 2 : len;
  unsigned char buf[512];
  while (take > 0) {
    size_t n = take < sizeof(buf) ? take : sizeof(buf);
    int got = evbuffer_remove(in, buf, n);
    if (got <= 0) break;
    take -= (size_t)got;
  }
}

static void write_cb(struct bufferevent *bev, void *ctx) {}

static void event_cb(struct bufferevent *bev, short what, void *ctx) {
  struct app_state *app = (struct app_state *)ctx;
  /* The usual pattern: drop the connection on EOF / error / timeout. */
  if (app->free_on_eof &&
      (what & (BEV_EVENT_EOF | BEV_EVENT_ERROR | BEV_EVENT_TIMEOUT)) &&
      bev == app->top) {
    bufferevent_free(bev);
    app->top = NULL;
  }
}

/* ---- harness ------------------------------------------------------------ */

static void drain_peer(int peer) {
  char buf[4096];
  while (recv(peer, buf, sizeof(buf), MSG_DONTWAIT) > 0) {
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2) return 0;
  FuzzedDataProvider fdp(data, size);
  uint8_t cfg = fdp.ConsumeIntegral<uint8_t>();

  memset(&g_app, 0, sizeof(g_app));
  memset(g_codec, 0, sizeof(g_codec));
  g_codec[0].app = g_codec[1].app = &g_app;
  g_app.leave_data = cfg & 4;
  g_app.free_on_eof = cfg & 8;
  g_app.rec_size = 1 + ((cfg >> 4) * 16);

  int fds[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) return 0;
  evutil_make_socket_nonblocking(fds[0]);
  evutil_make_socket_nonblocking(fds[1]);
  int peer = fds[1];

  vclock_reset();
  struct event_base *base = event_base_new();
  if (base) vclock_check_in_use();
  if (!base) {
    close(fds[0]);
    close(fds[1]);
    return 0;
  }

  int opts = BEV_OPT_CLOSE_ON_FREE;
  if (cfg & 1) opts |= BEV_OPT_DEFER_CALLBACKS;
  struct bufferevent *sock = bufferevent_socket_new(base, fds[0], opts);
  struct bufferevent *top = NULL;
  if (sock) {
    top = bufferevent_filter_new(sock, decode_records, encode_records, opts,
                                 NULL, &g_codec[0]);
    if (!top) bufferevent_free(sock);
  } else {
    close(fds[0]);
  }
  if (top && (cfg & 2)) {
    /* A second layer, e.g. compression on top of a record layer. */
    struct bufferevent *outer = bufferevent_filter_new(
        top, decode_records, encode_records, opts, NULL, &g_codec[1]);
    if (outer)
      top = outer;
  }
  if (!top) {
    close(peer);
    event_base_free(base);
    return 0;
  }
  g_app.top = top;
  bufferevent_setcb(top, read_cb, write_cb, event_cb, &g_app);
  bufferevent_enable(top, EV_READ | EV_WRITE);

  for (int op = 0; op < MAX_OPS && fdp.remaining_bytes() > 0 && g_app.top;
       op++) {
    top = g_app.top;
    uint8_t opcode = fdp.ConsumeIntegral<uint8_t>();
    switch (opcode % 12) {
      case 0: { /* the peer sends bytes */
        std::vector<uint8_t> chunk = fdp.ConsumeBytes<uint8_t>(
            fdp.ConsumeIntegralInRange<uint16_t>(0, MAX_CHUNK));
        if (peer >= 0 && !chunk.empty())
          send(peer, chunk.data(), chunk.size(), MSG_NOSIGNAL);
        break;
      }
      case 1: /* the peer reads what we sent */
        if (peer >= 0) drain_peer(peer);
        break;
      case 2: { /* the application sends data */
        std::vector<uint8_t> chunk = fdp.ConsumeBytes<uint8_t>(
            fdp.ConsumeIntegralInRange<uint16_t>(0, MAX_CHUNK));
        bufferevent_write(top, chunk.data(), chunk.size());
        break;
      }
      case 3: { /* the application flushes */
        uint8_t f = fdp.ConsumeIntegral<uint8_t>();
        static const short io[] = {EV_READ, EV_WRITE, EV_READ | EV_WRITE};
        static const enum bufferevent_flush_mode modes[] = {
            BEV_NORMAL, BEV_FLUSH, BEV_FINISHED};
        bufferevent_flush(top, io[f % 3], modes[(f / 3) % 3]);
        break;
      }
      case 4: { /* enable / disable reading or writing */
        uint8_t f = fdp.ConsumeIntegral<uint8_t>();
        short what = (f & 1) ? EV_READ : EV_WRITE;
        if (f & 2)
          bufferevent_disable(top, what);
        else
          bufferevent_enable(top, what);
        break;
      }
      case 5: { /* watermarks on the top layer or the one below it */
        uint8_t f = fdp.ConsumeIntegral<uint8_t>();
        size_t lo = fdp.ConsumeIntegralInRange<uint16_t>(0, 512);
        size_t hi = fdp.ConsumeIntegralInRange<uint16_t>(0, 1024);
        struct bufferevent *target = top;
        if ((f & 4) && bufferevent_get_underlying(top))
          target = bufferevent_get_underlying(top);
        bufferevent_setwatermark(target, (f & 1) ? EV_READ : EV_WRITE, lo,
                                 hi);
        size_t glo, ghi;
        bufferevent_getwatermark(target, (f & 2) ? EV_READ : EV_WRITE, &glo,
                                 &ghi);
        break;
      }
      case 6: { /* read / write timeouts */
        uint8_t f = fdp.ConsumeIntegral<uint8_t>();
        struct timeval rtv = {1 + (f & 3), 0};
        struct timeval wtv = {1 + ((f >> 2) & 3), 0};
        if (f & 0x40)
          bufferevent_settimeout(top, (f & 0x10) ? 0 : 2,
                                 (f & 0x20) ? 0 : 3);
        else
          bufferevent_set_timeouts(top, (f & 0x10) ? NULL : &rtv,
                                   (f & 0x20) ? NULL : &wtv);
        break;
      }
      case 7:
      case 8: /* time passes: the next deadline is reached */
        vclock_tick(base);
        break;
      case 9: { /* the peer half-closes or goes away */
        if (peer < 0) break;
        if (fdp.ConsumeBool()) {
          shutdown(peer, SHUT_WR);
        } else {
          close(peer);
          peer = -1;
        }
        break;
      }
      case 10: { /* the application pokes its callbacks */
        uint8_t f = fdp.ConsumeIntegral<uint8_t>();
        int topt = (f & 2) ? BEV_TRIG_DEFER_CALLBACKS : 0;
        if (f & 4) topt |= BEV_TRIG_IGNORE_WATERMARKS;
        if (f & 1)
          bufferevent_trigger(top, (f & 8) ? EV_READ : EV_WRITE, topt);
        else
          bufferevent_trigger_event(top, BEV_EVENT_EOF, topt);
        break;
      }
      case 11: { /* the application reconnects on a fresh socket */
        int nfds[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, nfds) != 0) break;
        evutil_make_socket_nonblocking(nfds[0]);
        evutil_make_socket_nonblocking(nfds[1]);
        if (bufferevent_replacefd(top, nfds[0]) == 0) {
          if (peer >= 0) close(peer);
          peer = nfds[1];
        } else {
          close(nfds[0]);
          close(nfds[1]);
        }
        bufferevent_get_enabled(top);
        break;
      }
    }
    event_base_loop(base, EVLOOP_NONBLOCK);
  }

  if (g_app.top) bufferevent_free(g_app.top);
  g_app.top = NULL;
  event_base_loop(base, EVLOOP_NONBLOCK);
  if (peer >= 0) close(peer);
  event_base_free(base);
  return 0;
}
