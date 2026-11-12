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
 * Fuzzer for the evdns DNS server (server side of evdns.c).
 *
 * Threat model: an application uses libevent to run a DNS server and any
 * remote client sends it requests, as UDP datagrams or as a TCP byte stream
 * (2-byte length framed, possibly split or coalesced arbitrarily by the
 * sender). The client controls every byte it sends.
 *
 * What an application does with a request is not attacker input, so the
 * request callback here behaves like an ordinary small server: for each
 * question it adds a record of the matching type whose owner name is the
 * question name, optionally an NS/glue pair, and then responds or drops.
 * That drives the response encoder (evdns_server_request_format_response(),
 * dnsname_to_labels() and its compression table, truncation) with
 * attacker-chosen names - the existing dns_fuzzer answers with an empty
 * response and only over UDP, so neither the encoder nor the TCP transport
 * (evdns_add_server_port_with_listener(), tcp_read_message()) is exercised.
 *
 * Input layout (consumed in this order):
 *   u8  mode   bit0: TCP instead of UDP
 *              bit1: (TCP) client closes before the server port is closed
 *              bit2: (TCP) limit the port to one client connection and
 *                    have a second client connect as well
 *   u8  plan   how the server application answers (see request_cb)
 *   then up to MAX_CHUNKS chunks, each:
 *     u16 len  (0..MAX_CHUNK)
 *     u8[len]  one UDP datagram, or the next slice of the TCP stream
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
#include "event2/dns.h"
#include "event2/dns_struct.h"
#include "event2/event.h"
#include "event2/listener.h"
#include "event2/util.h"
}

#define MAX_CHUNKS 8
#define MAX_CHUNK 1500

static uint8_t g_plan;

static void log_cb(int severity, const char *msg) {}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  event_set_log_callback(log_cb);
  /* Like any network program: a peer that went away must surface as a
   * write error, not kill the process. */
  signal(SIGPIPE, SIG_IGN);
  return 0;
}

/* A plain DNS server application. g_plan selects between a few ordinary
 * behaviours:
 *   bits 0-1  3: drop the request, otherwise respond
 *   bit 2     set the AA flag
 *   bit 3     add an NS record and glue (authority / additional sections)
 *   bits 4-7  response code
 */
static void request_cb(struct evdns_server_request *req, void *arg) {
  static const unsigned char v4[8] = {192, 0, 2, 1, 192, 0, 2, 2};
  static const unsigned char v6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                       0,    0,    0,    0,    0, 0, 0, 1};
  static const char txt[] = "\x0bhello world";

  if ((g_plan & 3) == 3) {
    evdns_server_request_drop(req);
    return;
  }

  for (int i = 0; i < req->nquestions; i++) {
    const struct evdns_server_question *q = req->questions[i];
    switch (q->type) {
      case EVDNS_TYPE_A:
        evdns_server_request_add_a_reply(req, q->name, 2, v4, 300);
        break;
      case EVDNS_TYPE_AAAA:
        evdns_server_request_add_aaaa_reply(req, q->name, 1, v6, 300);
        break;
      case EVDNS_TYPE_PTR:
        evdns_server_request_add_ptr_reply(req, NULL, q->name,
                                           "host.example.com", 300);
        break;
      case EVDNS_TYPE_CNAME:
        evdns_server_request_add_cname_reply(req, q->name,
                                             "target.example.com", 300);
        break;
      case EVDNS_TYPE_TXT:
        evdns_server_request_add_reply(req, EVDNS_ANSWER_SECTION, q->name,
                                       EVDNS_TYPE_TXT, EVDNS_CLASS_INET, 300,
                                       sizeof(txt) - 1, 0, txt);
        break;
      default:
        break;
    }
    if (g_plan & 8) {
      evdns_server_request_add_reply(req, EVDNS_AUTHORITY_SECTION, q->name,
                                     EVDNS_TYPE_NS, EVDNS_CLASS_INET, 60, -1,
                                     1, "ns.example.com");
      evdns_server_request_add_reply(req, EVDNS_ADDITIONAL_SECTION,
                                     "ns.example.com", EVDNS_TYPE_A,
                                     EVDNS_CLASS_INET, 60, 4, 0,
                                     (const char *)v4);
    }
  }

  if (g_plan & 4) evdns_server_request_set_flags(req, EVDNS_FLAGS_AA);

  /* A negative return means the response could not be built and the request
   * is still owned by the caller. */
  if (evdns_server_request_respond(req, g_plan >> 4) < 0)
    evdns_server_request_drop(req);
}

static void drain(int fd) {
  char buf[4096];
  while (recv(fd, buf, sizeof(buf), MSG_DONTWAIT) > 0) {
  }
}

static void fuzz_udp(struct event_base *base, FuzzedDataProvider &fdp) {
  int fds[2];
  if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, fds))
    return;
  struct evdns_server_port *port =
      evdns_add_server_port_with_base(base, fds[0], 0, request_cb, NULL);
  if (!port) {
    close(fds[0]);
    close(fds[1]);
    return;
  }
  for (int i = 0; i < MAX_CHUNKS && fdp.remaining_bytes() > 0; i++) {
    size_t len = fdp.ConsumeIntegralInRange<uint16_t>(0, MAX_CHUNK);
    std::vector<uint8_t> pkt = fdp.ConsumeBytes<uint8_t>(len);
    send(fds[1], pkt.data(), pkt.size(), 0);
    event_base_loop(base, EVLOOP_NONBLOCK);
    drain(fds[1]);
  }
  /* Closes fds[0]. */
  evdns_close_server_port(port);
  close(fds[1]);
}

static void fuzz_tcp(struct event_base *base, FuzzedDataProvider &fdp,
                     uint8_t mode) {
  struct sockaddr_in sin;
  socklen_t slen = sizeof(sin);
  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  struct evconnlistener *listener = evconnlistener_new_bind(
      base, NULL, NULL, LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1,
      (struct sockaddr *)&sin, sizeof(sin));
  if (!listener) return;
  /* The port takes ownership of the listener. */
  struct evdns_server_port *port =
      evdns_add_server_port_with_listener(base, listener, 0, request_cb, NULL);
  if (!port) {
    evconnlistener_free(listener);
    return;
  }
  if (mode & 4)
    evdns_server_port_set_option(port, EVDNS_SOPT_TCP_MAX_CLIENTS, 1);

  int client = -1;
  if (getsockname(evconnlistener_get_fd(listener), (struct sockaddr *)&sin,
                  &slen) == 0) {
    client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (client >= 0 &&
        connect(client, (struct sockaddr *)&sin, sizeof(sin)) != 0) {
      close(client);
      client = -1;
    }
  }

  int extra = -1;
  if (client >= 0) {
    /* Accept the connection. */
    event_base_loop(base, EVLOOP_NONBLOCK);
    if (mode & 4) {
      /* A second client, which is over the connection limit. */
      extra = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
      if (extra >= 0)
        (void)connect(extra, (struct sockaddr *)&sin, sizeof(sin));
      event_base_loop(base, EVLOOP_NONBLOCK);
    }
    for (int i = 0; i < MAX_CHUNKS && fdp.remaining_bytes() > 0; i++) {
      size_t len = fdp.ConsumeIntegralInRange<uint16_t>(0, MAX_CHUNK);
      std::vector<uint8_t> chunk = fdp.ConsumeBytes<uint8_t>(len);
      if (send(client, chunk.data(), chunk.size(),
               MSG_NOSIGNAL | MSG_DONTWAIT) < 0)
        break;
      event_base_loop(base, EVLOOP_NONBLOCK);
      drain(client);
    }
    if (mode & 2) {
      close(client);
      client = -1;
      /* Deliver the EOF to the server. */
      event_base_loop(base, EVLOOP_NONBLOCK);
    }
  }

  evdns_close_server_port(port);
  if (client >= 0) close(client);
  if (extra >= 0) close(extra);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 3) return 0;
  FuzzedDataProvider fdp(data, size);
  uint8_t mode = fdp.ConsumeIntegral<uint8_t>();
  g_plan = fdp.ConsumeIntegral<uint8_t>();

  struct event_base *base = event_base_new();
  if (!base) return 0;

  if (mode & 1)
    fuzz_tcp(base, fdp, mode);
  else
    fuzz_udp(base, fdp);

  event_base_loop(base, EVLOOP_NONBLOCK);
  event_base_free(base);
  return 0;
}
