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
 * dnsmasq_fuzzer_dhcp.c — libFuzzer harness for DHCPv4 processing.
 *
 * Intended for integration into the Google oss-fuzz project.
 * https://github.com/google/oss-fuzz
 *
 * Directly injects fuzz data into daemon->dhcp_packet and calls dhcp_reply()
 * from rfc2131.c, bypassing any stdin/loop mechanics in dhcp.c entirely.
 * This gives clean single-input semantics and covers:
 *   - rfc2131.c  dhcp_reply()       — full DHCPv4 message handling
 *   - rfc2131.c  relay_upstream4()  — client→server relay forwarding
 *   - rfc2131.c  relay_reply4()     — server→client relay reply routing
 *   - dhcp-common.c                 — option_filter(), match_netid(),
 *                                     match_netid_wild(), match_bytes(),
 *                                     run_tag_if(), config_has_mac(), ...
 *
 * Build (oss-fuzz environment — called from build.sh):
 *   $CC $CFLAGS -DVERSION='"oss-fuzz"' -Isrc \
 *       -o $OUT/dnsmasq_fuzzer_dhcp \
 *       fuzzing/oss-fuzz/dnsmasq_fuzzer_dhcp.c \
 *       <all dnsmasq objects except dnsmasq.o> \
 *       $LIB_FUZZING_ENGINE
 *
 * Local libFuzzer build (for development):
 *   make CC=clang \
 *        CFLAGS="-g -O1 -fsanitize=address,fuzzer-no-link" \
 *        LDFLAGS="-g -fsanitize=address -fsanitize=fuzzer" \
 *        FUZZER_DRIVER="" \
 *        mostly_clean oss_fuzz_dhcp
 */

#include "dnsmasq.h"
#include <net/if.h>

/* Fixed timestamp — keeps all time-dependent branches deterministic. */
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

/* ── Context chain setup ──────────────────────────────────────────────── */
/*
 * Replicates the AFL path inside complete_context() (dhcp.c) without needing
 * access to that static function.  Must be called before each dhcp_reply()
 * invocation so that context->current chain is rebuilt from scratch.
 */
static struct dhcp_context *build_context_chain(int iface_index)
{
  struct in_addr lo, mask, bcast;
  struct dhcp_context *ctx, *chain = NULL;

  (void)iface_index;

  lo.s_addr    = htonl(0x7f000001); /* 127.0.0.1       */
  mask.s_addr  = htonl(0xff000000); /* 255.0.0.0       */
  bcast.s_addr = htonl(0x7fffffff); /* 127.255.255.255 */

  /* reset the "unlinked" marker on every context */
  for (ctx = daemon->dhcp; ctx; ctx = ctx->next)
    ctx->current = ctx;

  /* link contexts whose range falls within the loopback subnet */
  for (ctx = daemon->dhcp; ctx; ctx = ctx->next)
    {
      if (!is_same_net(lo, ctx->start, mask) ||
          !is_same_net(lo, ctx->end,   mask))
        continue;

      ctx->local  = lo;
      ctx->router = lo;

      if (!(ctx->flags & CONTEXT_NETMASK))
        ctx->netmask = mask;

      if (!(ctx->flags & CONTEXT_BRDCAST))
        ctx->broadcast = bcast;

      ctx->current = chain;
      chain = ctx;
    }

  return chain;
}

/* ── One-time initialization ─────────────────────────────────────────── */
int LLVMFuzzerInitialize(int *argc, char ***argv)
{
  (void)argc; (void)argv;

  static char *fuzz_argv[] = {
    "fuzz_dhcp_reply",
    "--no-daemon",
    "--no-resolv",
    "--no-hosts",
    "--port=0",
    "--interface=lo",
    "--no-ping",
    /* set: tag makes context->netid.net non-NULL → option_filter context_tags branch */
    "--dhcp-range=set:myrange,127.0.0.100,127.0.0.200,12h",
    "--dhcp-authoritative",
    "--dhcp-generate-names",
    "--dhcp-broadcast",
    "--dhcp-lease-max=150",
    "--pxe-service=0,boot",
    /* CONFIG_HWADDR → find_config() MAC path */
    "--dhcp-host=de:ad:be:ef:00:01,127.0.0.150,testhost",
    /* CONFIG_CLID → find_config() client-id path */
    "--dhcp-host=id:ff:00:01:02:03:04:05,127.0.0.152,clid-host",
    "--dhcp-option=option:router,127.0.0.1",
    "--dhcp-option=option:dns-server,127.0.0.1",
    /* negative-tag → match_netid() '!' branch */
    "--dhcp-option=tag:!pxe,option:ntp-server,127.0.0.1",
    /* opt60 match → match_bytes() non-RFC3925 path */
    "--dhcp-vendorclass=set:pxe,PXEClient",
    /* RFC3925 opt124 match → match_bytes() nested enterprise path */
    "--dhcp-vendorclass=set:entclass,enterprise:12345,PXEClient",
    /* run_tag_if() → match_netid_wild() */
    "--tag-if=set:myclass,tag:pxe",
    /*
     * dhcp_match entries — the ONLY way to reach match_bytes() in dhcp-common.c.
     * --dhcp-vendorclass uses its own memcmp loop and never calls match_bytes().
     * --dhcp-match populates daemon->dhcp_match which is iterated at rfc2131.c:437.
     *   non-RFC3925: option_find(opt60) → match_bytes() at line 469
     *   RFC3925:     option_find(opt124) → match_bytes() at line 457 (nested blocks)
     */
    "--dhcp-match=set:opt60match,option:vendor-class,PXEClient",
    "--dhcp-match=set:opt77match,option:user-class,finance",
    "--dhcp-match=set:opt124match,vi-encap:12345,PXEClient",
    /*
     * --log-dhcp sets OPT_LOG_OPTS → covers log_options() and log_tags() and
     * all the "if (option_bool(OPT_LOG_OPTS))" branches in dhcp_reply/do_options.
     * log-facility=/dev/null absorbs the output.
     */
    "--log-dhcp",
    /*
     * --dhcp-delay triggers apply_delay() at rfc2131.c:1046 and 1361.
     * Value 0 means no actual delay but the code path is entered.
     */
    "--dhcp-reply-delay=0",
    /*
     * Normal relay entry.  iface_index is patched to lo after dhcp_init()
     * since read_opts() leaves it 0.
     * Triggers: relay_upstream4() line 3087 (!split_mode && iface_index match)
     *           relay_reply4()     line 3254 (giaddr == relay->local)
     */
    "--dhcp-relay=127.0.0.1,127.0.0.254",
    /*
     * Split-mode relay entry.
     *   local  = 127.0.0.1  (client-facing addr, must equal iface_addr)
     *   server = 127.0.0.254 (upstream)
     *   iface  = lo          (server-facing interface)
     * Triggers: relay_upstream4() line 3102 (split_mode && local == iface_addr)
     *           relay_reply4()     line 3239 (split_mode && giaddr == uplink)
     */
    "--dhcp-split-relay=127.0.0.1,127.0.0.254,lo",
    /*
     * DHCPLEASEQUERY (RFC 4388): covers lines 1067-1235 in rfc2131.c.
     * Without this, mess_type==DHCPLEASEQUERY returns 0 at line 1070.
     */
    "--leasequery",
    /*
     * Rapid-commit: OPT_RAPID_COMMIT → goto rapid_commit at rfc2131.c:1372.
     */
    "--dhcp-rapid-commit",
    /*
     * CONTEXT_PROXY range.  Enables proxy DHCP path (lines 964-1051) for
     * PXE DISCOVERs via the PXE proxy loop at line 969.
     */
    "--dhcp-range=127.0.0.1,proxy",
    /*
     * daemon->override=1: relay server-id override at rfc2131.c:858-870.
     */
    "--dhcp-proxy",
    /*
     * OPT_FQDN_UPDATE → FQDN flags manipulation at rfc2131.c:713-727.
     */
    "--dhcp-client-update",
    /*
     * MATCH_CIRCUIT / MATCH_REMOTE in agent-id sub-option loop (rfc2131.c:220).
     */
    "--dhcp-circuitid=set:circuit1,mycirc",
    "--dhcp-remoteid=set:remote1,myremote",
    /* discard lease file writes to avoid file-I/O non-determinism */
    "--dhcp-leasefile=/dev/null",
    "--log-facility=/dev/null",
  };
  int fuzz_argc = (int)(sizeof(fuzz_argv) / sizeof(fuzz_argv[0]));

  read_opts(fuzz_argc, fuzz_argv, "");

  /* mirror dnsmasq.c initialisation that read_opts skips */
  daemon->dumpfd = -1;
  if (daemon->edns_pktsz < PACKETSZ)
    daemon->edns_pktsz = PACKETSZ;
  daemon->packet_buff_sz = daemon->edns_pktsz + MAXDNAME + RRFIXEDSZ;
  daemon->packet = safe_malloc(daemon->packet_buff_sz);

  dhcp_common_init();
  lease_init(FUZZ_NOW);
  dhcp_init();   /* creates daemon->dhcpfd bound to port 0 on lo */

  /*
   * Patch relay4 iface_index to the loopback interface.
   * read_opts() leaves iface_index=0; without this, relay_upstream4()'s
   * !split_mode && iface_index check is always false.
   */
  {
    int lo_idx = (int)if_nametoindex("lo");
    struct dhcp_relay *r;
    for (r = daemon->relay4; r; r = r->next)
      if (!r->split_mode && r->iface_index == 0)
        r->iface_index = lo_idx;
  }

  return 0;
}

/* ── Per-input processing ────────────────────────────────────────────── */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  /* Drop inputs too small to be a valid DHCP fixed header */
  if (size < sizeof(struct dhcp_packet) - sizeof(((struct dhcp_packet *)0)->options))
    return 0;

  /* Inject fuzz data directly into the shared DHCP packet buffer */
  if (!expand_buf(&daemon->dhcp_packet, size))
    return 0;
  memcpy(daemon->dhcp_packet.iov_base, data, size);

  /* Resolve the loopback interface index; fail fast if lo is absent */
  int iface_index = (int)if_nametoindex("lo");
  if (iface_index == 0)
    return 0;

  struct in_addr lo;
  lo.s_addr = htonl(0x7f000001); /* server identifier / fallback address */

  struct dhcp_packet *mess = (struct dhcp_packet *)daemon->dhcp_packet.iov_base;

  /*
   * Pre-create a lease for the known MAC host so that dhcp_reply()'s
   * "if (lease)" branches (RENEWING/REBINDING/RELEASE/ACK-with-existing-lease)
   * are reachable without needing to discover a full DISCOVER→ACK exchange.
   *
   * lease4_allocate() returns NULL if a lease already exists for that address
   * (harmless — lease_prune() at the end of each input removes it).
   */
  {
    struct in_addr seed_addr;
    seed_addr.s_addr = htonl(0x7f000096); /* 127.0.0.150 — matches dhcp-host MAC entry */
    struct dhcp_lease *seed_lease = lease4_allocate(seed_addr);
    if (seed_lease)
      {
        static const unsigned char seed_mac[] = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x01};
        lease_set_hwaddr(seed_lease, seed_mac, NULL, 6, ARPHRD_ETHER, 0, FUZZ_NOW, 0);
        lease_set_expires(seed_lease, 43200, FUZZ_NOW);
        lease_set_interface(seed_lease, iface_index, FUZZ_NOW);
      }
  }

  /* Reset per-iteration relay state (mirrors dhcp_packet() line 383) */
  {
    struct dhcp_relay *r;
    for (r = daemon->relay4; r; r = r->next)
      r->matchcount = 0;
  }

  /*
   * relay_reply4() — rfc2131.c
   *
   * Returns non-zero when the packet is a BOOTREPLY (op=2) from an upstream
   * server to be forwarded back to a DHCP client via us as relay.
   * Mirrors dhcp_packet() line 350.
   */
  if (relay_reply4(mess, size, "lo") != 0)
    goto done;

  /*
   * relay_upstream4() — rfc2131.c
   *
   * Forwards a BOOTREQUEST from a client upstream toward the DHCP server.
   * Only acts when mess->op == BOOTREQUEST && mess->hops <= 20 and a
   * matching relay4 entry exists.  Safe to call unconditionally.
   * The actual sendto() to 127.0.0.254 will fail gracefully.
   *
   * Mirrors dhcp_packet() line 424.
   */
  relay_upstream4(lo, iface_index, mess, size, /*unicast=*/1);

  /* Build the dhcp_context chain for 127.0.0.0/8 */
  {
    struct dhcp_context *ctx = build_context_chain(iface_index);
    if (!ctx)
      goto done;

    /* Prune expired leases before processing */
    lease_prune(NULL, FUZZ_NOW);

    int is_inform = 0;
    dhcp_reply(ctx, "lo", iface_index, size, FUZZ_NOW,
               /*unicast_dest=*/1, /*loopback=*/1,
               &is_inform, /*pxe=*/0, lo, FUZZ_NOW, lo);
  }

  /* Sync lease state; no-ops when leasefile=/dev/null */
  lease_update_file(FUZZ_NOW);
  lease_update_dns(0);

done:
  /* Reset leases so every input starts from a clean slate */
  /* Prune all leases: any lease seeded or created by dhcp*_reply() expires
   * well before time 2000000 (FUZZ_NOW=1000000, max expiry 1000000+43200).
   * lease_reset_all() is not in upstream dnsmasq. */
  lease_prune(NULL, (time_t)2000000);

  return 0;
}
