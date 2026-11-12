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
 * Fuzzer for the time-driven part of the evdns stub resolver: retransmits,
 * request timeouts, nameserver failure / probing / recovery, reassignment
 * of requests between nameservers, the waiting queue, the getaddrinfo
 * A/AAAA skew timer, cache TTL expiry, runtime nameserver addition and
 * reconfiguration, and resolver shutdown.
 *
 * Threat model: the application resolves names through libevent against
 * several nameservers. The DNS infrastructure it talks to (or an on-path
 * attacker) decides, per query, whether and when a reply arrives, which
 * nameserver answers, the response code, truncation, the TCP fallback
 * behaviour and the reply bytes. The application's configuration is
 * trusted and picked from a few representative setups.
 *
 * evdns_client_fuzzer answers every query from a single server without
 * time ever passing, so none of the timer callbacks run and all of the
 * nameserver bookkeeping (nameserver_failed(), nameserver_send_probe(),
 * nameserver_probe_callback(), request_swap_ns(),
 * retransmit_all_tcp_requests_for(), evdns_getaddrinfo_timeout_cb(),
 * evdns_ttl_expired(), evdns_requests_pump_waiting_queue(),
 * evdns_base_clear_nameservers_and_suspend(), evdns_base_free(), ...)
 * stays unreached. Those paths juggle request ownership between lists and
 * nameservers, which is where lifetime bugs live.
 *
 * Time is virtual (virtual_clock.h): libevent's clock stands still and the
 * "tick" operation moves it forward to the earliest pending deadline, so
 * every timer due then fires, exactly as if that much time had passed.
 * This keeps every input fast (no sleeping) and its timer order a pure
 * function of the input.
 *
 * Every input is self-contained, so a crash reproduces from its input alone
 * in a fresh process and never depends on earlier inputs:
 *  - the clock, the fake nameservers' sockets, the event_base and the
 *    evdns_base are created or reset for each input and destroyed at its
 *    end, and all harness globals are reset;
 *  - the randomness inside evdns (transaction ids and 0x20 case
 *    randomisation) does not affect behaviour: max-inflight is capped so
 *    the in-flight requests are kept in one list in creation order instead
 *    of being hashed by transaction id, the fake servers echo the id and
 *    question from the query, and names are compared case-insensitively
 *    when case randomisation is on.
 *
 * Input layout (consumed in this order):
 *   u8  cfg   bits 0-1: number of nameservers - 1 (1..3)
 *             bit2: no cache, bit3: search domains,
 *             bit4: max-inflight 1 instead of 5 (both use the waiting
 *                   queue; see the note where it is set),
 *             bit5: max-timeouts 1 / attempts 1, bit6: randomize-case off
 *             bit7: shut down with evdns_base_free(dns, 1), failing the
 *                   outstanding lookups, instead of cancelling them first
 *   then up to MAX_OPS operations: u8 opcode + operands (see the switch)
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <string>
#include <vector>

#include <fuzzer/FuzzedDataProvider.h>

#include "virtual_clock.h"

extern "C" {
#include "event2/dns.h"
#include "event2/event.h"
#include "event2/util.h"
}

#define NUM_NS 3
#define MAX_REQS 8
#define MAX_OPS 48
#define MAX_BODY 1024

/* The fake nameservers: UDP + TCP on the same loopback port. Created
 * afresh for every input and closed at its end. */
struct fake_ns {
  int udp;
  int tcp;
  int conn; /* accepted TCP connection from the resolver, or -1 */
  std::vector<uint8_t> tcp_in;
  struct sockaddr_in addr;
  char addr_str[64];
};
static struct fake_ns g_ns[NUM_NS];

/* One slot per lookup the application started. */
struct lookup {
  int pending; /* 1 until the callback has run */
  struct evdns_request *req;
  struct evdns_getaddrinfo_request *gai;
};
static struct lookup g_lookups[MAX_REQS];

static void log_cb(int severity, const char *msg) {}

static void resolve_cb(int result, char type, int count, int ttl,
                       void *addresses, void *arg) {
  struct lookup *l = (struct lookup *)arg;
  l->pending = 0;
  l->req = NULL;
  /* Touch the result the way an application would. */
  volatile unsigned char sink = 0;
  if (result == DNS_ERR_NONE && addresses) {
    const unsigned char *p = (const unsigned char *)addresses;
    size_t n = 0;
    if (type == DNS_IPv4_A) {
      n = (size_t)count * 4;
    } else if (type == DNS_IPv6_AAAA) {
      n = (size_t)count * 16;
    } else if (type == DNS_PTR && count > 0) {
      p = (const unsigned char *)*(char **)addresses;
      n = strlen((const char *)p);
    }
    for (size_t i = 0; i < n; i++) sink ^= p[i];
  }
}

static void gai_cb(int result, struct evutil_addrinfo *res, void *arg) {
  struct lookup *l = (struct lookup *)arg;
  l->pending = 0;
  l->gai = NULL;
  volatile size_t sink = 0;
  for (struct evutil_addrinfo *ai = res; ai; ai = ai->ai_next) {
    if (ai->ai_canonname) sink += strlen(ai->ai_canonname);
    const unsigned char *p = (const unsigned char *)ai->ai_addr;
    for (size_t i = 0; p && i < ai->ai_addrlen; i++) sink += p[i];
  }
  if (res) evutil_freeaddrinfo(res);
}

static int make_ns(struct fake_ns *ns) {
  for (int attempt = 0; attempt < 16; attempt++) {
    struct sockaddr_in sin;
    socklen_t slen = sizeof(sin);
    int one = 1;
    int udp = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    int tcp = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (udp >= 0 && tcp >= 0) {
      memset(&sin, 0, sizeof(sin));
      sin.sin_family = AF_INET;
      sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
      setsockopt(tcp, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
      if (bind(udp, (struct sockaddr *)&sin, sizeof(sin)) == 0 &&
          getsockname(udp, (struct sockaddr *)&sin, &slen) == 0 &&
          bind(tcp, (struct sockaddr *)&sin, sizeof(sin)) == 0 &&
          listen(tcp, 16) == 0) {
        ns->udp = udp;
        ns->tcp = tcp;
        ns->conn = -1;
        ns->addr = sin;
        snprintf(ns->addr_str, sizeof(ns->addr_str), "127.0.0.1:%d",
                 ntohs(sin.sin_port));
        return 0;
      }
    }
    if (udp >= 0) close(udp);
    if (tcp >= 0) close(tcp);
  }
  return -1;
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  event_set_log_callback(log_cb);
  signal(SIGPIPE, SIG_IGN);
  return 0;
}

static void close_servers(void) {
  for (int i = 0; i < NUM_NS; i++) {
    struct fake_ns *ns = &g_ns[i];
    if (ns->conn >= 0) close(ns->conn);
    if (ns->tcp >= 0) close(ns->tcp);
    if (ns->udp >= 0) close(ns->udp);
    ns->conn = ns->tcp = ns->udp = -1;
    ns->tcp_in.clear();
  }
}

/* Fresh sockets for every input, so nothing a previous input sent or left
 * queued can reach this one. */
static int open_servers(void) {
  for (int i = 0; i < NUM_NS; i++) {
    g_ns[i].udp = g_ns[i].tcp = g_ns[i].conn = -1;
    g_ns[i].tcp_in.clear();
  }
  for (int i = 0; i < NUM_NS; i++) {
    if (make_ns(&g_ns[i]) != 0) {
      close_servers();
      return -1;
    }
  }
  return 0;
}

/* ---- reply construction ------------------------------------------------ */

/* Offset just behind the first question of a query, or 0 if malformed. */
static size_t question_end(const uint8_t *q, size_t n) {
  size_t i = 12;
  while (i < n && q[i] != 0) {
    if (q[i] > 63) return 0;
    i += (size_t)q[i] + 1;
  }
  i += 1 + 4; /* root label, qtype, qclass */
  return i <= n ? i : 0;
}

static void put16(std::vector<uint8_t> &v, unsigned x) {
  v.push_back((uint8_t)(x >> 8));
  v.push_back((uint8_t)x);
}

/*
 * Build the reply to query q according to rmode:
 *   0: raw - id from the query, the rest of the header and everything after
 *      the (optionally echoed) question come from the fuzz body
 *   1: a well-formed positive answer of the queried type
 *   2: an empty answer with a fuzz-chosen header (rcode / TC / counts)
 * Bit 2 of rmode controls whether the question is echoed in mode 0.
 */
static std::vector<uint8_t> build_reply(const uint8_t *q, size_t n,
                                        uint8_t rmode,
                                        const std::vector<uint8_t> &body) {
  std::vector<uint8_t> out;
  size_t qend = question_end(q, n);
  out.push_back(q[0]);
  out.push_back(q[1]);
  switch (rmode & 3) {
    case 1: {
      uint16_t qtype = qend >= 16 ? (uint16_t)((q[qend - 4] << 8) | q[qend - 3])
                                  : 1;
      uint8_t ttl = body.empty() ? 30 : body[0];
      put16(out, 0x8180); /* response, RD, RA, NOERROR */
      put16(out, qend ? 1 : 0);
      put16(out, 1);
      put16(out, 0);
      put16(out, 0);
      if (qend) out.insert(out.end(), q + 12, q + qend);
      put16(out, 0xc00c); /* owner: the question name */
      put16(out, qtype);
      put16(out, 1);
      put16(out, 0);
      put16(out, ttl);
      if (qtype == 28) {
        static const uint8_t a6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                       0,    0,    0,    0,    0, 0, 0, 1};
        put16(out, 16);
        out.insert(out.end(), a6, a6 + 16);
      } else if (qtype == 12 || qtype == 5) {
        static const uint8_t nm[] = {4, 'h', 'o', 's', 't', 4,
                                     't', 'e', 's', 't', 0};
        put16(out, sizeof(nm));
        out.insert(out.end(), nm, nm + sizeof(nm));
      } else {
        static const uint8_t a4[4] = {192, 0, 2, 1};
        put16(out, 4);
        out.insert(out.end(), a4, a4 + 4);
      }
      break;
    }
    case 2: {
      uint8_t f = body.size() > 0 ? body[0] : 0;
      uint8_t rc = body.size() > 1 ? body[1] : 2;
      /* QR always set; opcode/AA/TC/RD from f; RA + rcode from rc. */
      out.push_back((uint8_t)(0x80 | (f & 0x7f)));
      out.push_back(rc);
      put16(out, qend ? 1 : 0);
      put16(out, 0);
      put16(out, 0);
      put16(out, 0);
      if (qend) out.insert(out.end(), q + 12, q + qend);
      break;
    }
    default: {
      size_t hdr = body.size() < 10 ? body.size() : 10;
      out.insert(out.end(), body.begin(), body.begin() + hdr);
      out.resize(12, 0);
      if ((rmode & 4) && qend) out.insert(out.end(), q + 12, q + qend);
      out.insert(out.end(), body.begin() + hdr, body.end());
      break;
    }
  }
  return out;
}

/* Answer (or drop) the oldest UDP query waiting at nameserver ns. */
static void serve_udp(struct fake_ns *ns, uint8_t rmode, bool drop,
                      const std::vector<uint8_t> &body) {
  uint8_t q[4096];
  struct sockaddr_in from;
  socklen_t fromlen = sizeof(from);
  ssize_t n =
      recvfrom(ns->udp, q, sizeof(q), 0, (struct sockaddr *)&from, &fromlen);
  if (n < 12 || drop) return;
  std::vector<uint8_t> out = build_reply(q, (size_t)n, rmode, body);
  sendto(ns->udp, out.data(), out.size(), 0, (struct sockaddr *)&from,
         fromlen);
}

/* Act as the TCP side of nameserver ns: accept, then answer one framed
 * query or drop the connection. */
static void serve_tcp(struct event_base *base, struct fake_ns *ns,
                      uint8_t rmode, bool close_conn,
                      const std::vector<uint8_t> &body) {
  if (ns->conn < 0) {
    ns->conn = accept4(ns->tcp, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (ns->conn < 0) return;
    ns->tcp_in.clear();
    event_base_loop(base, EVLOOP_NONBLOCK);
  }
  if (close_conn) {
    close(ns->conn);
    ns->conn = -1;
    ns->tcp_in.clear();
    return;
  }
  uint8_t buf[4096];
  ssize_t r;
  while ((r = recv(ns->conn, buf, sizeof(buf), 0)) > 0)
    ns->tcp_in.insert(ns->tcp_in.end(), buf, buf + r);
  if (r == 0) {
    close(ns->conn);
    ns->conn = -1;
    ns->tcp_in.clear();
    return;
  }
  if (ns->tcp_in.size() < 2) return;
  size_t qlen = ((size_t)ns->tcp_in[0] << 8) | ns->tcp_in[1];
  if (qlen < 12 || ns->tcp_in.size() < 2 + qlen) return;
  std::vector<uint8_t> out =
      build_reply(ns->tcp_in.data() + 2, qlen, rmode, body);
  ns->tcp_in.erase(ns->tcp_in.begin(), ns->tcp_in.begin() + 2 + qlen);
  uint8_t pfx[2] = {(uint8_t)(out.size() >> 8), (uint8_t)out.size()};
  out.insert(out.begin(), pfx, pfx + 2);
  send(ns->conn, out.data(), out.size(), MSG_NOSIGNAL);
}

static void add_nameserver(struct evdns_base *dns, int i) {
  /* Exercise both ways of adding a nameserver. */
  if (i == 2)
    evdns_base_nameserver_sockaddr_add(dns, (struct sockaddr *)&g_ns[i].addr,
                                       sizeof(g_ns[i].addr), 0);
  else
    evdns_base_nameserver_ip_add(dns, g_ns[i].addr_str);
}

static void start_lookup(struct evdns_base *dns, FuzzedDataProvider &fdp) {
  uint8_t kind = fdp.ConsumeIntegral<uint8_t>();
  std::string name = fdp.ConsumeRandomLengthString(64);
  if (name.c_str()[0] == '\0') name = "www.example.com";
  int slot = -1;
  for (int i = 0; i < MAX_REQS; i++)
    if (!g_lookups[i].pending) {
      slot = i;
      break;
    }
  if (slot < 0) return;
  struct lookup *l = &g_lookups[slot];
  int flags = 0;
  if (kind & 0x10) flags |= DNS_QUERY_NO_SEARCH;
  if (kind & 0x20) flags |= DNS_QUERY_USEVC;
  if (kind & 0x40) flags |= DNS_QUERY_IGNTC;
  l->pending = 1;
  l->req = NULL;
  l->gai = NULL;
  switch (kind % 5) {
    case 0:
      l->req = evdns_base_resolve_ipv4(dns, name.c_str(), flags, resolve_cb, l);
      break;
    case 1:
      l->req = evdns_base_resolve_ipv6(dns, name.c_str(), flags, resolve_cb, l);
      break;
    case 2: {
      struct in_addr a;
      a.s_addr = htonl(0xc0000201);
      l->req = evdns_base_resolve_reverse(dns, &a, flags, resolve_cb, l);
      break;
    }
    case 3: {
      struct in6_addr a6;
      memset(&a6, 0, sizeof(a6));
      a6.s6_addr[15] = 1;
      l->req = evdns_base_resolve_reverse_ipv6(dns, &a6, flags, resolve_cb, l);
      break;
    }
    case 4: {
      struct evutil_addrinfo hints;
      memset(&hints, 0, sizeof(hints));
      hints.ai_family = (kind & 0x80) ? AF_INET : AF_UNSPEC;
      hints.ai_socktype = SOCK_STREAM;
      hints.ai_flags = EVUTIL_AI_CANONNAME;
      /* May call back synchronously and return NULL. */
      l->gai = evdns_getaddrinfo(dns, name.c_str(), "53", &hints, gai_cb, l);
      return;
    }
  }
  /* The resolve functions return NULL without calling back on failure. */
  if (!l->req) l->pending = 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2) return 0;
  FuzzedDataProvider fdp(data, size);
  uint8_t cfg = fdp.ConsumeIntegral<uint8_t>();

  memset(g_lookups, 0, sizeof(g_lookups));
  if (open_servers() != 0) return 0;

  vclock_reset();
  struct event_base *base = event_base_new();
  if (!base) {
    close_servers();
    return 0;
  }
  vclock_check_in_use();
  struct evdns_base *dns =
      evdns_base_new(base, (cfg & 4) ? EVDNS_BASE_NO_CACHE : 0);
  if (!dns) {
    event_base_free(base);
    close_servers();
    return 0;
  }

  int nns = 1 + (cfg & 3) % NUM_NS;
  if (cfg & 8) {
    evdns_base_search_add(dns, "a.test");
    evdns_base_search_add(dns, "b.test");
    evdns_base_search_ndots_set(dns, 2);
  }
  /* At most 5 requests in flight keeps evdns's in-flight table to a single
   * list (evdns.c keeps (max_inflight + 4) / 5 lists, hashed by the random
   * transaction id), so requests are walked, retransmitted and timed out in
   * the order they were made rather than in an order that changes from run
   * to run. Further requests wait in the waiting queue. */
  evdns_base_set_option(dns, "max-inflight:", (cfg & 16) ? "1" : "5");
  if (cfg & 32) {
    evdns_base_set_option(dns, "max-timeouts:", "1");
    evdns_base_set_option(dns, "attempts:", "1");
  } else {
    evdns_base_set_option(dns, "max-timeouts:", "2");
    evdns_base_set_option(dns, "attempts:", "3");
  }
  if (cfg & 64) evdns_base_set_option(dns, "randomize-case:", "0");
  evdns_base_set_option(dns, "timeout:", "2.5");
  evdns_base_set_option(dns, "getaddrinfo-allow-skew:", "0.5");
  evdns_base_set_option(dns, "initial-probe-timeout:", "1");
  evdns_base_set_option(dns, "max-probe-timeout:", "8");
  evdns_base_set_option(dns, "probe-backoff-factor:", "2");
  for (int i = 0; i < nns; i++) add_nameserver(dns, i);

  for (int op = 0; op < MAX_OPS && fdp.remaining_bytes() > 0; op++) {
    uint8_t opcode = fdp.ConsumeIntegral<uint8_t>();
    switch (opcode % 8) {
      case 0:
        start_lookup(dns, fdp);
        break;
      case 1:   /* a nameserver answers (or drops) a UDP query */
      case 2: { /* likewise over TCP */
        uint8_t sel = fdp.ConsumeIntegral<uint8_t>();
        size_t len = fdp.ConsumeIntegralInRange<uint16_t>(0, MAX_BODY);
        std::vector<uint8_t> body = fdp.ConsumeBytes<uint8_t>(len);
        struct fake_ns *ns = &g_ns[(sel & 3) % NUM_NS];
        uint8_t rmode = sel >> 2;
        bool drop = (rmode & 0x38) == 0x38;
        if (opcode % 8 == 1)
          serve_udp(ns, rmode, drop, body);
        else
          serve_tcp(base, ns, rmode, drop, body);
        break;
      }
      case 3:
      case 4:
        /* Time passes: the next deadline is reached. */
        vclock_tick(base);
        break;
      case 5: { /* the application gives up on a lookup */
        struct lookup *l =
            &g_lookups[fdp.ConsumeIntegral<uint8_t>() % MAX_REQS];
        /* The handles stay valid until the callback runs; cancel each one
         * at most once. */
        if (l->pending) {
          if (l->req) evdns_cancel_request(dns, l->req);
          if (l->gai) evdns_getaddrinfo_cancel(l->gai);
          l->req = NULL;
          l->gai = NULL;
        }
        break;
      }
      case 6: { /* the application changes its nameserver configuration */
        uint8_t f = fdp.ConsumeIntegral<uint8_t>();
        if (f & 0x80) {
          /* Reconfigure, e.g. after a network change: drop all
           * nameservers, add the new set, resume. */
          evdns_base_clear_nameservers_and_suspend(dns);
          for (int i = 0; i < NUM_NS; i++)
            if (f & (1 << i)) add_nameserver(dns, i);
          evdns_base_resume(dns);
        } else {
          /* Add one more nameserver. */
          add_nameserver(dns, (f & 3) % NUM_NS);
        }
        break;
      }
      case 7: { /* the application inspects its configuration */
        int n = evdns_base_count_nameservers(dns);
        struct sockaddr_storage ss;
        int idx = fdp.ConsumeIntegralInRange<int>(0, 3);
        evdns_base_get_nameserver_addr(dns, idx, (struct sockaddr *)&ss,
                                       sizeof(ss));
        evdns_base_get_nameserver_fd(dns, idx);
        (void)n;
        break;
      }
    }
    event_base_loop(base, EVLOOP_NONBLOCK);
  }

  /* Shutdown, in one of the two ways an application does it. */
  if (cfg & 0x80) {
    /* Free the resolver and let it fail whatever is still in flight
     * (DNS_ERR_SHUTDOWN callbacks), then keep running the loop. */
    evdns_base_free(dns, 1);
  } else {
    /* Cancel the outstanding lookups, let the cancellation callbacks run,
     * then free the resolver. */
    for (int round = 0; round < 4; round++) {
      bool any = false;
      for (int i = 0; i < MAX_REQS; i++) {
        struct lookup *l = &g_lookups[i];
        if (!l->pending) continue;
        any = true;
        if (l->req) evdns_cancel_request(dns, l->req);
        if (l->gai) evdns_getaddrinfo_cancel(l->gai);
        l->req = NULL;
        l->gai = NULL;
      }
      if (!any) break;
      event_base_loop(base, EVLOOP_NONBLOCK);
    }
    evdns_base_free(dns, 0);
  }
  event_base_loop(base, EVLOOP_NONBLOCK);
  event_base_free(base);
  close_servers();
  return 0;
}
