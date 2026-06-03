/*
 * dnsmasq_fuzzer_dns.c — libFuzzer harness for DNS packet processing.
 *
 * Intended for integration into the Google oss-fuzz project.
 * https://github.com/google/oss-fuzz
 *
 * Exercises the full rfc1035.c function suite plus edns0.c and rrfilter.c
 * with fuzz data treated as raw DNS wire-format packets.  Coverage:
 *   extract_request, extract_name (all 4 modes), skip_name/questions/section
 *   answer_request (with/without AD+DO), extract_addresses (with/without
 *   rebind check), setup_reply, do_doctor, check_for_bogus_wildcard,
 *   check_for_ignored_address, check_for_local_domain, in_arpa_name_2_addr,
 *   private_net / private_net6, resize_packet, find_pseudoheader,
 *   add_pseudoheader, add_resource_record, rrfilter (EDNS0+DNSSEC modes).
 *
 * Build (oss-fuzz environment — called from build.sh):
 *   $CC $CFLAGS -DVERSION='"oss-fuzz"' -Isrc \
 *       -o $OUT/dnsmasq_fuzzer_dns \
 *       fuzzing/oss-fuzz/dnsmasq_fuzzer_dns.c \
 *       <all dnsmasq objects except dnsmasq.o> \
 *       $LIB_FUZZING_ENGINE
 *
 * Local libFuzzer build (for development):
 *   make CC=clang \
 *        CFLAGS="-g -O1 -fsanitize=address,fuzzer-no-link" \
 *        LDFLAGS="-g -fsanitize=address -fsanitize=fuzzer" \
 *        FUZZER_DRIVER="" \
 *        mostly_clean oss_fuzz_dns
 */

#include "dnsmasq.h"
#include <time.h>

/* Fixed timestamp — keeps all time-dependent branches deterministic.
 * Using time(NULL) causes TTL comparisons and negative-cache checks to flip
 * between the fuzzer's two stability-measurement runs, tanking stability. */
#define FUZZ_NOW ((time_t)1000000)

/* dnsmasq.c owns this global; we define it here since we don't link dnsmasq.o */
struct daemon *daemon;

/* ── Stubs for functions defined in dnsmasq.c ─────────────────────────── */
void send_event(int fd, int event, int data, char *msg)
  { (void)fd; (void)event; (void)data; (void)msg; }
void queue_event(int event)               { (void)event; }
void send_alarm(time_t event, time_t now) { (void)event; (void)now; }
int  icmp_ping(struct in_addr addr)       { (void)addr; return 0; }
int  delay_dhcp(time_t start, int sec, int fd, uint32_t addr, unsigned short id)
  { (void)start; (void)sec; (void)fd; (void)addr; (void)id; return 0; }

/* ── One-time initialization ─────────────────────────────────────────── */
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
    "fuzz_dns",
    "--keep-in-foreground",
    "--no-resolv",
    "--no-hosts",
    "--port=0",
    "--cache-size=512",
    /* Records that answer_request() can serve */
    "--host-record=host.fuzz.test,192.0.2.1,2001:db8::1",
    "--mx-host=fuzz.test,mail.fuzz.test,10",
    "--txt-record=fuzz.test,v=spf1 ~all",
    "--cname=alias.fuzz.test,host.fuzz.test",
    "--srv-host=_http._tcp.fuzz.test,host.fuzz.test,80",
    /* address= populates F_CONFIG A answers */
    "--address=/fuzz.test/192.0.2.1",
    /* Bogus-wildcard detection: marks 198.105.254.11 as a lie */
    "--bogus-nxdomain=198.105.254.11",
    /* Rebind check for extract_addresses */
    "--stop-dns-rebind",
    /* NAT-alias / do_doctor path */
    "--alias=10.0.0.1,192.0.2.1",
    "--log-facility=/dev/null",
  };
  int fuzz_argc = (int)(sizeof(fuzz_argv) / sizeof(fuzz_argv[0]));

  read_opts(fuzz_argc, fuzz_argv, "");

  /* Route all my_syslog() calls to /dev/null instead of falling back to vsyslog() */
  log_start(NULL, -1);

  /* Post-read_opts initialisation, matching dnsmasq.c */
  daemon->dumpfd = -1;

  if (daemon->edns_pktsz < PACKETSZ)
    daemon->edns_pktsz = PACKETSZ;
  daemon->packet_buff_sz = daemon->edns_pktsz + MAXDNAME + RRFIXEDSZ;
  daemon->packet = safe_malloc(daemon->packet_buff_sz);

  cache_init();
  blockdata_init();

  return 0;
}

/* ── Per-input processing ────────────────────────────────────────────── */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  /* Need at least a DNS header (12 bytes). */
  if (size < sizeof(struct dns_header))
    return 0;

  /*
   * Expire all dynamic cache entries so every iteration starts from a clean
   * slate.  Setting ttd=0 on each non-immortal entry makes cache_find_by_name/
   * addr skip them (both call is_expired() which returns 1 when ttd < now).
   * Immortal entries (F_IMMORTAL) from --host-record / --address / etc. are
   * unaffected because is_expired() returns 0 for them regardless of ttd.
   *
   * We do NOT call cache_init() here: that function safe_malloc's a fresh
   * crec array without freeing the previous one, so repeated calls grow the
   * LRU list unboundedly and corrupt eviction order.
   */
  {
    struct crec *crec;
    cache_enumerate(1);
    while ((crec = cache_enumerate(0)))
      crec->ttd = 0;
  }

  /* Working copy — many callers write back into the buffer. */
  static unsigned char buf[65536];
  size_t capped = size < sizeof(buf) ? size : sizeof(buf);
  memcpy(buf, data, capped);

  struct dns_header *header = (struct dns_header *)buf;
  time_t now = FUZZ_NOW;

  /* ── 1. extract_request ─────────────────────────────────────────────────── */
  char name[MAXDNAME*2+1];
  unsigned short qtype = 0, qclass = 0;
  extract_request(header, capped, name, &qtype, &qclass);

  /* ── 2. extract_name (all four modes) ──────────────────────────────────── */
  {
    char name2[MAXDNAME*2+1];
    unsigned char *pp;

    pp = (unsigned char *)(header + 1);
    extract_name(header, capped, &pp, name2, EXTR_NAME_EXTRACT, 0);

    pp = (unsigned char *)(header + 1);
    extract_name(header, capped, &pp, name2, EXTR_NAME_COMPARE, 0);

    pp = (unsigned char *)(header + 1);
    extract_name(header, capped, &pp, name2, EXTR_NAME_NOCASE, 0);

    pp = (unsigned char *)(header + 1);
    extract_name(header, capped, &pp, name2, EXTR_NAME_FLIP, 0);
  }

  /* ── 3. skip_* pointer traversal ───────────────────────────────────────── */
  {
    unsigned char *p = skip_questions(header, capped);
    if (p)
      {
        skip_name(p, header, capped, 0);
        skip_section(p, (int)ntohs(header->ancount), header, capped);
      }
  }

  /* ── 4. answer_request: serve from configured local records / cache ─────── */
  {
    static unsigned char abuf[65536];
    size_t alen = capped;
    memcpy(abuf, data, alen);
    struct dns_header *ah = (struct dns_header *)abuf;
    char *alimit = (char *)abuf + sizeof(abuf);
    struct in_addr local  = { .s_addr = htonl(0xc0000201) }; /* 192.0.2.1 */
    struct in_addr mask   = { .s_addr = htonl(0xffffff00) }; /* /24 */
    int stale = 0, filtered = 0;

    /* plain query (no AD/DO) */
    answer_request(ah, alimit, alen, local, mask, now, 0, 0, 0, &stale, &filtered);

    /* with AD and DO bits requested */
    memcpy(abuf, data, alen);
    ah->hb4 |= HB4_AD;
    answer_request(ah, alimit, alen, local, mask, now, 1, 1, 0, &stale, &filtered);
  }

  /* ── 5. extract_addresses: parse fuzz data as upstream response ─────────── */
  {
    static unsigned char ebuf[65536];
    memcpy(ebuf, data, capped);
    struct dns_header *eh = (struct dns_header *)ebuf;
    char ename[MAXDNAME*2+1];

    /* Mark as a DNS response (QR=1) */
    eh->hb3 |= HB3_QR;

    /* Without rebind check */
    extract_addresses(eh, capped, ename, now, NULL, NULL, 0, 0, 0);

    /* With rebind check (exercises OPT_NO_REBIND path) */
    memcpy(ebuf, data, capped);
    eh->hb3 |= HB3_QR;
    extract_addresses(eh, capped, ename, now, NULL, NULL, 1, 0, 0);
  }

  /* ── 6. setup_reply with several flag combinations ──────────────────────── */
  {
    static unsigned char sbuf[sizeof(struct dns_header)];
    memcpy(sbuf, buf, sizeof(sbuf));
    struct dns_header *sh = (struct dns_header *)sbuf;

    setup_reply(sh, F_NOERR,    EDE_UNSET);
    setup_reply(sh, F_NXDOMAIN, EDE_UNSET);
    setup_reply(sh, F_NEG,      EDE_OTHER);
    setup_reply(sh, 0,          EDE_FILTERED);
  }

  /* ── 7. do_doctor: NAT address rewriting in responses ───────────────────── */
  {
    static unsigned char dbuf[65536];
    memcpy(dbuf, data, capped);
    struct dns_header *dh = (struct dns_header *)dbuf;
    dh->hb3 |= HB3_QR; /* responses only */
    do_doctor(dh, capped, daemon->namebuff);
  }

  /* ── 8. check_for_bogus_wildcard ────────────────────────────────────────── */
  check_for_bogus_wildcard(header, capped, daemon->namebuff, now);

  /* ── 9. check_for_ignored_address ───────────────────────────────────────── */
  check_for_ignored_address(header, capped);

  /* ── 10. check_for_local_domain ─────────────────────────────────────────── */
  if (name[0])
    check_for_local_domain(name, now);

  /* ── 11. in_arpa_name_2_addr ────────────────────────────────────────────── */
  if (name[0])
    {
      union all_addr arpa;
      in_arpa_name_2_addr(name, &arpa);
    }

  /* ── 12. private_net / private_net6 ─────────────────────────────────────── */
  {
    struct in_addr a4;
    memset(&a4, 0, sizeof(a4));
    if (capped >= sizeof(a4))
      memcpy(&a4, data, sizeof(a4));

    struct in6_addr a6;
    memset(&a6, 0, sizeof(a6));
    if (capped >= sizeof(a6))
      memcpy(&a6, data, sizeof(a6));

    private_net(a4, 0);
    private_net(a4, 1);
    private_net6(&a6, 0);
    private_net6(&a6, 1);
  }

  /* ── 13. find_pseudoheader + resize_packet ──────────────────────────────── */
  {
    static unsigned char pbuf[65536];
    memcpy(pbuf, data, capped);
    struct dns_header *ph = (struct dns_header *)pbuf;

    size_t        optsz    = 0;
    unsigned char *optp    = NULL;
    int           is_sign  = 0, is_last = 0;
    unsigned char *opt_start =
      find_pseudoheader(ph, capped, &optsz, &optp, &is_sign, &is_last);

    if (opt_start)
      resize_packet(ph, capped, opt_start, optsz);
  }

  /* ── 14. add_pseudoheader (add EDE option) ──────────────────────────────── */
  {
    static unsigned char pbuf2[65536];
    memcpy(pbuf2, data, capped);
    struct dns_header *ph2 = (struct dns_header *)pbuf2;
    add_pseudoheader(ph2, capped, pbuf2 + sizeof(pbuf2),
                     EDNS0_OPTION_EDE, NULL, 0, 0, 0);
  }

  /* ── 15. add_resource_record (fixed A record into a scratch header) ──────── */
  {
    static unsigned char rbuf[65536];
    memset(rbuf, 0, sizeof(struct dns_header));
    struct dns_header *rh  = (struct dns_header *)rbuf;
    unsigned char     *rp  = rbuf + sizeof(struct dns_header);
    int truncated = 0;
    struct in_addr addr4   = { .s_addr = htonl(0xc0000201) }; /* 192.0.2.1 */

    add_resource_record(rh, (char *)rbuf + sizeof(rbuf), &truncated,
                        sizeof(struct dns_header), &rp,
                        300, NULL, T_A, C_IN, "4", &addr4);
  }

  /* ── 16. rrfilter: strip EDNS0 then DNSSEC ──────────────────────────────── */
  {
    static unsigned char fbuf[65536];
    size_t flen;

    memcpy(fbuf, data, capped);
    flen = capped;
    rrfilter((struct dns_header *)fbuf, &flen, RRFILTER_EDNS0);

    memcpy(fbuf, data, capped);
    flen = capped;
    rrfilter((struct dns_header *)fbuf, &flen, RRFILTER_DNSSEC);
  }

  return 0;
}
