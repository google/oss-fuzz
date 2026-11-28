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
 * dnsmasq_fuzzer_forward.c — libFuzzer harness for the dnsmasq forwarding
 *                            pipeline.
 *
 * Intended for integration into the Google oss-fuzz project.
 * https://github.com/google/oss-fuzz
 *
 * Exercises the upstream-reply processing path unique to forward.c:
 *
 *   return_reply()
 *     → process_reply()
 *         → find_pseudoheader()         (EDNS0 opt parsing)
 *         → check_for_bogus_wildcard()  (spoofed-NXDOMAIN detection)
 *         → check_for_ignored_address() (--bogus-nxdomain filter)
 *         → do_doctor()                 (NAT-alias address rewriting)
 *         → extract_addresses()         (cache insertion from reply RRs)
 *         → rrfilter()                  (strip EDNS0 / DNSSEC RRs)
 *         → add_pseudoheader()          (EDE option injection)
 *     → flip_queryname()                (case-scramble reversal, multi-client)
 *     → truncation path                 (reply > one client's UDP size limit)
 *     → free_frec()                     (forwarding-record lifecycle)
 *
 * Three flag combinations are tested per input so different branches of
 * process_reply() and return_reply() are reached:
 *
 *   (a) flags=0, two frec_src clients
 *       → flip_queryname() exercised; second client's small udp_pkt_size
 *         triggers the truncation loop
 *   (b) FREC_NOREBIND | FREC_DO_QUESTION | FREC_HAS_PHEADER, one client
 *       → rebind check skipped for this forward; EDNS0 pseudo-header kept
 *   (c) FREC_CHECKING_DISABLED | FREC_AD_QUESTION, one client
 *       → CD bit preserved in reply; AD bit handling
 *
 * Build (oss-fuzz environment — called from build.sh):
 *   $CC $CFLAGS -DVERSION='"oss-fuzz"' -Isrc \
 *       -o $OUT/dnsmasq_fuzzer_forward \
 *       fuzzing/oss-fuzz/dnsmasq_fuzzer_forward.c \
 *       <all dnsmasq objects except dnsmasq.o> \
 *       $LIB_FUZZING_ENGINE
 *
 * Local libFuzzer build (for development):
 *   make CC=clang \
 *        CFLAGS="-g -O1 -fsanitize=address,fuzzer-no-link" \
 *        LDFLAGS="-g -fsanitize=address -fsanitize=fuzzer" \
 *        FUZZER_DRIVER="" \
 *        mostly_clean oss_fuzz_forward
 */

#include "dnsmasq.h"
#include <time.h>

/* Fixed timestamp — keeps all time-dependent branches deterministic.
 * Using time(NULL) causes TTL comparisons and log-timestamp branches to flip
 * between the fuzzer's two stability-measurement runs, tanking stability. */
#define FUZZ_NOW ((time_t)1000000)

/* dnsmasq.c owns this global; we redefine it here since dnsmasq.o is excluded. */
struct daemon *daemon;

/* ── Stubs for dnsmasq.c-defined symbols ─────────────────────────────────── */
void send_event(int fd, int event, int data, char *msg)
  { (void)fd; (void)event; (void)data; (void)msg; }
void queue_event(int event) { (void)event; }
void send_alarm(time_t event, time_t now) { (void)event; (void)now; }
int  icmp_ping(struct in_addr addr) { (void)addr; return 0; }
int  delay_dhcp(time_t start, int sec, int fd, uint32_t addr, unsigned short id)
  { (void)start; (void)sec; (void)fd; (void)addr; (void)id; return 0; }

/* ── Objects reused across iterations ────────────────────────────────────── */

/* A single frec is pre-allocated and linked into daemon->frec_list.
   free_frec() (called at the end of return_reply()) zeroes sentto, flags,
   frec_src.next, stash, and rfds but does NOT free the frec struct itself,
   so we can safely re-populate and reuse it every iteration. */
static struct frec *fuzz_frec;

/* A minimal fake upstream server.  process_reply() references server->flags
   and prettyprint_addr(&server->addr, ...) but nothing requiring a live
   socket.  return_reply() only uses forward->sentto, not serverarray[]. */
static struct server fake_server;

/* ── One-time setup ──────────────────────────────────────────────────────── */

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
  (void)argc; (void)argv;

  /*
   * Do NOT redirect stdout/stderr here.  In LLVM 18+, LLVMFuzzerInitialize
   * is called BEFORE libfuzzer prints its own INFO lines, so redirecting
   * here would silence all fuzzer output.  Suppress dnsmasq log output via
   * --log-facility=/dev/null and log_start(NULL, -1) instead.
   */

  static char *fuzz_argv[] = {
    "fuzz_forward",
    "--keep-in-foreground",
    "--no-resolv",
    "--no-hosts",
    "--port=0",
    "--cache-size=512",
    /* Exercises the rebind-check path in process_reply() */
    "--stop-dns-rebind",
    "--rebind-domain-ok=fuzz.test",
    /* Exercises check_for_bogus_wildcard() / check_for_ignored_address() */
    "--bogus-nxdomain=198.105.254.11",
    /* Exercises do_doctor() NAT-alias rewriting in process_reply() */
    "--alias=10.0.0.1,192.0.2.1",
    /* Upstream server: read_opts() builds serverarray with one entry */
    "--server=127.0.0.1#5553",
    "--log-facility=/dev/null",
  };
  int fuzz_argc = (int)(sizeof(fuzz_argv) / sizeof(fuzz_argv[0]));

  read_opts(fuzz_argc, fuzz_argv, "");

  /* Route my_syslog() to /dev/null so it doesn't fall back to vsyslog(). */
  log_start(NULL, -1);

  /* Post-read_opts initialisation matching dnsmasq.c */
  daemon->dumpfd         = -1;
  daemon->pipe_to_parent = -1;
  daemon->srv_save       = NULL;

  if (daemon->edns_pktsz < PACKETSZ)
    daemon->edns_pktsz = PACKETSZ;
  daemon->packet_buff_sz = daemon->edns_pktsz + MAXDNAME + RRFIXEDSZ;
  daemon->packet = safe_malloc(daemon->packet_buff_sz);

  cache_init();
  blockdata_init();

  /* Pre-populate the frec_src free pool so free_frec() can return extra
     frec_src records to it and we can pull them back for the next call. */
  daemon->ftabsize       = 100;
  daemon->frec_src_count = 0;
  daemon->free_frec_src  = NULL;
  for (int i = 0; i < 16; i++)
    {
      struct frec_src *s = safe_malloc(sizeof(struct frec_src));
      memset(s, 0, sizeof(*s));
      s->next = daemon->free_frec_src;
      daemon->free_frec_src = s;
      daemon->frec_src_count++;
    }

  /* Pre-allocate the frec and link it into daemon->frec_list so that
     free_frec() won't try to free or allocate around it. */
  fuzz_frec = safe_malloc(sizeof(struct frec));
  memset(fuzz_frec, 0, sizeof(*fuzz_frec));
  fuzz_frec->next   = daemon->frec_list;
  daemon->frec_list = fuzz_frec;

  /* Minimal fake upstream server (used as forward->sentto). */
  memset(&fake_server, 0, sizeof(fake_server));
  fake_server.addr.sa.sa_family       = AF_INET;
  fake_server.addr.in.sin_addr.s_addr = htonl(0x7f000001); /* 127.0.0.1 */
  fake_server.addr.in.sin_port        = htons(5553);
  fake_server.last_server             = -1;

  return 0;
}

/* ── Per-input helper ────────────────────────────────────────────────────── */

/*
 * Build a frec with the given flags and call return_reply().
 *
 * If add_second_client is non-zero, a second frec_src is pulled from the
 * daemon free pool and linked as frec_src.next.  The second client has a
 * smaller udp_pkt_size (512 bytes) and a non-zero encode_bitmap, which
 * exercises both the truncation loop and flip_queryname() inside
 * return_reply().
 *
 * On return, free_frec() (called inside return_reply()) has:
 *   - set fuzz_frec->sentto = NULL, ->flags = 0, ->frec_src.next = NULL
 *   - returned the second frec_src (if any) to daemon->free_frec_src
 *   - left fuzz_frec->next intact (the frec stays in daemon->frec_list)
 *
 * Callers must re-populate fuzz_frec before the next call.
 */
static void call_return_reply(time_t now,
                               const uint8_t *data, size_t capped,
                               unsigned int frec_flags, int add_second_client)
{
  /* Copy fuzz data into daemon->packet so process_reply() can work on it
     in-place (it may shrink/expand the packet within the buffer). */
  memcpy(daemon->packet, data, capped);
  memset(daemon->packet + capped, 0, daemon->packet_buff_sz - capped);

  struct dns_header *hdr = (struct dns_header *)daemon->packet;

  /* process_reply() expects a DNS response (QR=1) with at least one
     question.  Set the minimum required bits without disturbing the rest of
     the fuzz-supplied header so we still reach deep parsing paths. */
  hdr->hb3 |= HB3_QR;
  if (ntohs(hdr->qdcount) == 0)
    hdr->qdcount = htons(1);

  /* ── Rebuild fuzz_frec (zeroed by free_frec() in the previous call) ───── */
  struct frec *fwd  = fuzz_frec;
  fwd->sentto       = &fake_server;
  fwd->flags        = frec_flags;
  fwd->new_id       = hdr->id;
  fwd->stash        = NULL;
  fwd->rfds         = NULL;
  fwd->forwardall   = 0;

  /* Primary client (embedded frec_src).  fd=-1 → return_reply() skips the
     actual send_from() call, so no real socket is required. */
  fwd->frec_src.fd                        = -1;
  fwd->frec_src.source.sa.sa_family       = AF_INET;
  fwd->frec_src.source.in.sin_addr.s_addr = htonl(0x7f000001); /* 127.0.0.1 */
  fwd->frec_src.source.in.sin_port        = htons(5353);
  fwd->frec_src.dest.addr4.s_addr         = htonl(0x7f000001);
  fwd->frec_src.orig_id                   = ntohs(hdr->id);
  fwd->frec_src.udp_pkt_size              = PACKETSZ; /* full-size allowed */
  fwd->frec_src.log_id                    = 1;
  fwd->frec_src.encode_bitmap             = 0;
  fwd->frec_src.encode_bigmap             = NULL;
  fwd->frec_src.next                      = NULL;

  /* Optional second client (exercises flip_queryname + truncation path). */
  if (add_second_client && daemon->free_frec_src)
    {
      struct frec_src *s2    = daemon->free_frec_src;
      daemon->free_frec_src  = s2->next;

      memset(s2, 0, sizeof(*s2));
      s2->fd                        = -1;
      s2->source.sa.sa_family       = AF_INET;
      s2->source.in.sin_addr.s_addr = htonl(0xc0000201); /* 192.0.2.1 */
      s2->source.in.sin_port        = htons(9999);
      s2->dest.addr4.s_addr         = htonl(0xc0000202);
      s2->udp_pkt_size              = 512;        /* smaller → truncation */
      s2->orig_id                   = ntohs(hdr->id) ^ 0x4242;
      s2->encode_bitmap             = 0xdeadbeef; /* non-zero → case flip */
      s2->encode_bigmap             = NULL;
      s2->log_id                    = 2;

      fwd->frec_src.next = s2;
    }

  /*
   * return_reply() → process_reply() → extract_addresses() / do_doctor() /
   * check_for_bogus_wildcard() / check_for_ignored_address() / rrfilter() /
   * add_pseudoheader() → per-frec_src delivery loop → flip_queryname() →
   * free_frec()
   *
   * STAT_OK == 0x70000; in non-DNSSEC builds `status' is immediately
   * voided so any value is fine.
   */
  return_reply(now, fwd, hdr, (ssize_t)capped, STAT_OK);

  /* free_frec() has now cleared fwd->sentto/flags/frec_src.next/stash/rfds.
     The frec struct memory is still valid (free_frec never calls free(f)).
     Callers may immediately re-populate and reuse fuzz_frec. */
}

/* ── Per-input entry point ───────────────────────────────────────────────── */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  /* Need at least a DNS header. */
  if (size < sizeof(struct dns_header))
    return 0;

  /* Cap at the packet buffer size; daemon->packet is the working area. */
  size_t capped = size < daemon->packet_buff_sz ? size : daemon->packet_buff_sz;
  time_t now    = FUZZ_NOW;

  /*
   * Expire all dynamic cache entries so every iteration starts from the same
   * state.  ttd=0 < FUZZ_NOW=1000000, so is_expired() returns 1 for them and
   * cache_find_by_name/addr skip them.  Immortal config entries are unaffected.
   *
   * We do NOT call cache_init() — it safe_malloc's without freeing the old crec
   * array, growing the LRU list unboundedly across persistent-mode iterations.
   */
  {
    struct crec *crec;
    cache_enumerate(1);
    while ((crec = cache_enumerate(0)))
      crec->ttd = 0;
  }

  /*
   * Reset fake_server mutable state.
   *
   * process_reply() sets server->flags |= SERV_WARNED_RECURSIVE the first time
   * it sees a reply without the RA bit.  Without a reset, iteration 1 sets the
   * flag and iterations 2-N skip the warning branch entirely — different coverage.
   *
   * server->nxdomain_replies is incremented on every NXDOMAIN reply; not a
   * branch itself, but domain-match.c uses it as a quality metric.
   */
  fake_server.flags            = 0;
  fake_server.nxdomain_replies = 0;
  daemon->srv_save             = NULL;

  /* ── 1. Plain reply — two clients ───────────────────────────────────────
   *
   * The second client has udp_pkt_size=512 and a non-zero encode_bitmap,
   * so if the processed reply is > 512 bytes both the truncation loop and
   * flip_queryname() are exercised.  If process_reply() shrinks the reply
   * to ≤ 512 bytes, flip_queryname() is still called for the second src.
   */
  call_return_reply(now, data, capped, /*flags=*/0, /*two_clients=*/1);

  /* ── 2. Rebind-exempt + EDNS0 passthrough + DO bit ─────────────────────
   *
   * FREC_NOREBIND:    skips the rebind check for this forward record
   * FREC_HAS_PHEADER: client sent EDNS0 → process_reply() keeps the
   *                   pseudo-header instead of stripping it
   * FREC_DO_QUESTION: client set DO bit → process_reply() advertises our
   *                   edns_pktsz back to the client
   */
  call_return_reply(now, data, capped,
                    FREC_NOREBIND | FREC_HAS_PHEADER | FREC_DO_QUESTION,
                    /*two_clients=*/0);

  /* ── 3. Checking-disabled + AD question ────────────────────────────────
   *
   * FREC_CHECKING_DISABLED: CD bit is preserved in the reply (no DNSSEC
   *                         validation was requested by the client)
   * FREC_AD_QUESTION:       client set AD bit → process_reply() may set
   *                         AD in the reply if the answer is secure
   */
  call_return_reply(now, data, capped,
                    FREC_CHECKING_DISABLED | FREC_AD_QUESTION,
                    /*two_clients=*/0);

  return 0;
}
