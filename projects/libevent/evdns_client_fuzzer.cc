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
 * Fuzzer for the evdns stub-resolver (client side of evdns.c).
 *
 * Threat model: the application resolves a host name through libevent and a
 * malicious (or spoofing, on-path) DNS server answers. The attacker sees the
 * query, so it knows the transaction id and the (0x20 case-randomised)
 * question, and controls every other byte of the reply, over UDP and - after
 * a truncated reply or with "use-vc" - over TCP.
 *
 * The harness therefore plays the name server on loopback: it reads each
 * query libevent sends, copies the transaction id (and optionally the
 * question section) out of it and fills in the rest of the reply from the
 * fuzz input. Without this, replies are discarded by the transaction-id and
 * question checks at the top of reply_parse() and nothing behind them
 * (answer/authority parsing, reply_handle(), search domains, CNAME handling,
 * evdns_getaddrinfo() merging, the cache, TCP framing) is ever reached.
 *
 * Input layout (consumed in this order):
 *   u8  cfg     resolver configuration, picked from a few representative
 *               setups (bit0 no-cache, bit1 randomize-case off, bit2 EDNS,
 *               bit3 search domain, bit4 hosts file, bit5 cancel at the end)
 *   u8  kind    which lookup API is used (see switch below)
 *   u8  qflags  DNS_QUERY_* / getaddrinfo hint selection
 *   str name    host name to resolve (random-length string, <= 100 bytes)
 *   then up to MAX_ROUNDS replies, each:
 *     u8  rmode   bit0: echo the question section of the query
 *                 bit1: (TCP) send the body raw, without the length prefix
 *     u16 len     body length (0..MAX_BODY)
 *     u8[len]     body: 10 bytes of header after the id (flags, counts),
 *                 then the bytes that follow the (optional) echoed question
 *
 * Every input is self-contained, so a crash reproduces from its input alone
 * in a fresh process and never depends on earlier inputs:
 *  - the fake name server's UDP and TCP sockets are created for each input
 *    and closed at its end, so nothing an earlier input sent or connected
 *    can be read by a later one;
 *  - time is virtual (virtual_clock.h) and reset for every input. It never
 *    advances here, so no evdns timeout fires, exactly as before, but no
 *    timer can fire because an input happened to run slowly either;
 *  - at most 5 requests are in flight, which keeps evdns's in-flight table
 *    to a single list in creation order. With more, requests are spread
 *    over several lists by their random transaction id, and
 *    evdns_base_free(dns, 1) would fail the A and AAAA halves of a
 *    getaddrinfo lookup in an order that changes from run to run. A lookup
 *    never has more than two requests in flight, so nothing is lost.
 */

#include <arpa/inet.h>
#include <fcntl.h>
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

extern "C" {
#include "event2/dns.h"
#include "event2/event.h"
#include "event2/util.h"
}

#include "virtual_clock.h"

#define MAX_ROUNDS 6
#define MAX_BODY 2048

/* The fake name server. Created for each input (see make_server_sockets). */
static int g_udp = -1;
static int g_tcp = -1;
static char g_ns_addr[64];
static char g_hosts_path[64];

struct query_state {
  int pending; /* number of callbacks that have not fired yet */
};

static void log_cb(int severity, const char *msg) {}

static void resolve_cb(int result, char type, int count, int ttl,
                       void *addresses, void *arg) {
  struct query_state *st = (struct query_state *)arg;
  st->pending--;
  /* Touch the result the way an application would, so that a short or
   * dangling result buffer is reported by the sanitizer. */
  volatile unsigned char sink = 0;
  if (result == DNS_ERR_NONE && addresses) {
    const unsigned char *p = (const unsigned char *)addresses;
    size_t n = 0;
    if (type == DNS_IPv4_A) {
      n = (size_t)count * 4;
    } else if (type == DNS_IPv6_AAAA) {
      n = (size_t)count * 16;
    } else if (type == DNS_PTR && count > 0) {
      n = strlen(*(char **)addresses);
      p = (const unsigned char *)*(char **)addresses;
    } else if (type == DNS_CNAME) {
      n = strlen((const char *)addresses);
    }
    for (size_t i = 0; i < n; i++) sink ^= p[i];
  }
}

static void gai_cb(int result, struct evutil_addrinfo *res, void *arg) {
  struct query_state *st = (struct query_state *)arg;
  st->pending--;
  volatile size_t sink = 0;
  for (struct evutil_addrinfo *ai = res; ai; ai = ai->ai_next) {
    if (ai->ai_canonname) sink += strlen(ai->ai_canonname);
    const unsigned char *p = (const unsigned char *)ai->ai_addr;
    for (size_t i = 0; p && i < ai->ai_addrlen; i++) sink += p[i];
  }
  if (res) evutil_freeaddrinfo(res);
}

static int make_server_sockets(void) {
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
      /* evdns talks UDP and TCP to the same address, so both sockets have to
       * share one port number. */
      if (bind(udp, (struct sockaddr *)&sin, sizeof(sin)) == 0 &&
          getsockname(udp, (struct sockaddr *)&sin, &slen) == 0 &&
          bind(tcp, (struct sockaddr *)&sin, sizeof(sin)) == 0 &&
          listen(tcp, 16) == 0) {
        g_udp = udp;
        g_tcp = tcp;
        snprintf(g_ns_addr, sizeof(g_ns_addr), "127.0.0.1:%d",
                 ntohs(sin.sin_port));
        return 0;
      }
    }
    if (udp >= 0) close(udp);
    if (tcp >= 0) close(tcp);
  }
  return -1;
}

static void close_server_sockets(void) {
  if (g_udp >= 0) close(g_udp);
  if (g_tcp >= 0) close(g_tcp);
  g_udp = g_tcp = -1;
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  event_set_log_callback(log_cb);
  /* Like any network program: a peer that went away must surface as a
   * write error, not kill the process. */
  signal(SIGPIPE, SIG_IGN);

  /* A fixed, trusted hosts file: it is application configuration, not
   * attacker input. It lets evdns_getaddrinfo() take its hosts-file path. */
  snprintf(g_hosts_path, sizeof(g_hosts_path), "/tmp/evdns_client_hosts.%d",
           (int)getpid());
  FILE *fp = fopen(g_hosts_path, "wb");
  if (fp) {
    fputs("127.0.0.1 localhost fuzzhost\n::1 localhost fuzzhost\n"
          "10.1.2.3 a.example.com\n",
          fp);
    fclose(fp);
  }
  return 0;
}

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

static std::vector<uint8_t> build_reply(const uint8_t *q, size_t n,
                                        uint8_t rmode,
                                        const std::vector<uint8_t> &body) {
  std::vector<uint8_t> out;
  size_t hdr = body.size() < 10 ? body.size() : 10;
  out.push_back(q[0]); /* transaction id of the query */
  out.push_back(q[1]);
  out.insert(out.end(), body.begin(), body.begin() + hdr);
  out.resize(12, 0);
  if (rmode & 1) {
    size_t qend = question_end(q, n);
    if (qend > 12) out.insert(out.end(), q + 12, q + qend);
  }
  out.insert(out.end(), body.begin() + hdr, body.end());
  return out;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 4) return 0;
  FuzzedDataProvider fdp(data, size);

  uint8_t cfg = fdp.ConsumeIntegral<uint8_t>();
  uint8_t kind = fdp.ConsumeIntegral<uint8_t>();
  uint8_t qflags = fdp.ConsumeIntegral<uint8_t>();
  std::string name = fdp.ConsumeRandomLengthString(100);
  if (name.c_str()[0] == '\0') name = "www.example.com";

  if (make_server_sockets() != 0) return 0;

  vclock_reset();
  struct event_base *base = event_base_new();
  if (!base) {
    close_server_sockets();
    return 0;
  }
  vclock_check_in_use();
  struct evdns_base *dns =
      evdns_base_new(base, (cfg & 1) ? EVDNS_BASE_NO_CACHE : 0);
  if (!dns) {
    event_base_free(base);
    close_server_sockets();
    return 0;
  }

  /* One in-flight list, in creation order (see the header comment). */
  evdns_base_set_option(dns, "max-inflight:", "5");
  if (cfg & 2) evdns_base_set_option(dns, "randomize-case:", "0");
  if (cfg & 4) evdns_base_set_option(dns, "edns-udp-size:", "4096");
  if (cfg & 8) {
    evdns_base_search_add(dns, "search.test");
    evdns_base_search_add(dns, "b.test");
    evdns_base_search_ndots_set(dns, 1);
  }
  if (cfg & 16) evdns_base_load_hosts(dns, g_hosts_path);
  evdns_base_nameserver_ip_add(dns, g_ns_addr);

  int flags = 0;
  if (qflags & 1) flags |= DNS_QUERY_NO_SEARCH;
  if (qflags & 2) flags |= DNS_QUERY_USEVC;
  if (qflags & 4) flags |= DNS_QUERY_IGNTC;
  if (qflags & 8) flags |= DNS_CNAME_CALLBACK;

  struct query_state st = {0};
  struct evdns_request *req = NULL;
  struct evdns_getaddrinfo_request *gai = NULL;

  switch (kind % 5) {
    case 0:
      st.pending = 1;
      req = evdns_base_resolve_ipv4(dns, name.c_str(), flags, resolve_cb, &st);
      break;
    case 1:
      st.pending = 1;
      req = evdns_base_resolve_ipv6(dns, name.c_str(), flags, resolve_cb, &st);
      break;
    case 2: {
      struct in_addr a;
      a.s_addr = htonl(0x01020304);
      st.pending = 1;
      req = evdns_base_resolve_reverse(dns, &a, flags, resolve_cb, &st);
      break;
    }
    case 3: {
      struct in6_addr a6;
      memset(&a6, 0, sizeof(a6));
      a6.s6_addr[15] = 1;
      st.pending = 1;
      req = evdns_base_resolve_reverse_ipv6(dns, &a6, flags, resolve_cb, &st);
      break;
    }
    case 4: {
      static const int families[] = {AF_UNSPEC, AF_INET, AF_INET6, AF_UNSPEC};
      struct evutil_addrinfo hints;
      memset(&hints, 0, sizeof(hints));
      hints.ai_family = families[(qflags >> 4) & 3];
      hints.ai_socktype = SOCK_STREAM;
      hints.ai_protocol = IPPROTO_TCP;
      if (qflags & 64) hints.ai_flags |= EVUTIL_AI_CANONNAME;
      st.pending = 1;
      gai = evdns_getaddrinfo(dns, name.c_str(), "80", &hints, gai_cb, &st);
      break;
    }
  }
  /* The resolve functions return NULL without calling back on failure. */
  if (kind % 5 != 4 && !req) st.pending = 0;

  int conn = -1; /* TCP connection from the resolver, once accepted */
  std::vector<uint8_t> tcp_in;

  for (int round = 0; round < MAX_ROUNDS && fdp.remaining_bytes() > 0;
       round++) {
    uint8_t rmode = fdp.ConsumeIntegral<uint8_t>();
    size_t len = fdp.ConsumeIntegralInRange<uint16_t>(0, MAX_BODY);
    std::vector<uint8_t> body = fdp.ConsumeBytes<uint8_t>(len);

    /* Let the resolver send its query / connect. */
    event_base_loop(base, EVLOOP_NONBLOCK);

    uint8_t q[4096];
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    ssize_t n = recvfrom(g_udp, q, sizeof(q), 0, (struct sockaddr *)&from,
                         &fromlen);
    if (n >= 12) {
      /* One UDP query is answered per round; further queries (search
       * domains, the AAAA half of getaddrinfo) wait for the next round. */
      std::vector<uint8_t> out = build_reply(q, (size_t)n, rmode, body);
      sendto(g_udp, out.data(), out.size(), 0, (struct sockaddr *)&from,
             fromlen);
    } else {
      if (conn < 0) {
        conn = accept4(g_tcp, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (conn >= 0) {
          tcp_in.clear();
          /* Let the resolver notice the connect and flush its query. */
          event_base_loop(base, EVLOOP_NONBLOCK);
        }
      }
      if (conn >= 0) {
        ssize_t r;
        while ((r = recv(conn, q, sizeof(q), 0)) > 0)
          tcp_in.insert(tcp_in.end(), q, q + r);
        if (r == 0) {
          /* The resolver dropped the connection. */
          close(conn);
          conn = -1;
          tcp_in.clear();
        } else if (tcp_in.size() >= 2) {
          size_t qlen = ((size_t)tcp_in[0] << 8) | tcp_in[1];
          if (qlen >= 12 && tcp_in.size() >= 2 + qlen) {
            std::vector<uint8_t> out =
                build_reply(tcp_in.data() + 2, qlen, rmode, body);
            tcp_in.erase(tcp_in.begin(), tcp_in.begin() + 2 + qlen);
            if (!(rmode & 2)) {
              uint8_t pfx[2] = {(uint8_t)(out.size() >> 8),
                                (uint8_t)out.size()};
              out.insert(out.begin(), pfx, pfx + 2);
            }
            send(conn, out.data(), out.size(), MSG_NOSIGNAL);
          }
        }
      }
    }

    /* Let the resolver parse the reply and run the deferred callbacks. */
    event_base_loop(base, EVLOOP_NONBLOCK);
  }

  /* An application giving up on the lookup. Only legal while the callback
   * has not run: afterwards the request handle is gone. */
  if ((cfg & 32) && st.pending > 0) {
    if (req) evdns_cancel_request(dns, req);
    if (gai) evdns_getaddrinfo_cancel(gai);
    event_base_loop(base, EVLOOP_NONBLOCK);
  }

  if (conn >= 0) close(conn);
  /* Fail whatever is still in flight, then run the resulting callbacks. */
  evdns_base_free(dns, 1);
  event_base_loop(base, EVLOOP_NONBLOCK);
  event_base_free(base);
  close_server_sockets();
  return 0;
}
