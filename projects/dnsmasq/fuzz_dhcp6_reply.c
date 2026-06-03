/*
 * dnsmasq_fuzzer_dhcp6.c — libFuzzer harness for DHCPv6 processing.
 *
 * Intended for integration into the Google oss-fuzz project.
 * https://github.com/google/oss-fuzz
 *
 * Directly injects fuzz data into daemon->dhcp_packet and calls dhcp6_reply()
 * from rfc3315.c, bypassing any stdin/loop mechanics in dhcp6.c entirely.
 * This gives clean single-input semantics and covers:
 *   - rfc3315.c  dhcp6_reply()       — full DHCPv6 message handling
 *   - rfc3315.c  relay_upstream6()   — client→server relay forwarding
 *   - rfc3315.c  relay_reply6()      — server→client relay reply routing
 *   - dhcp-common.c                  — option_filter(), match_netid(), ...
 *
 * Build (oss-fuzz environment — called from build.sh):
 *   $CC $CFLAGS -DVERSION='"oss-fuzz"' -Isrc \
 *       -o $OUT/dnsmasq_fuzzer_dhcp6 \
 *       fuzzing/oss-fuzz/dnsmasq_fuzzer_dhcp6.c \
 *       <all dnsmasq objects except dnsmasq.o> \
 *       $LIB_FUZZING_ENGINE
 *
 * Local libFuzzer build (for development):
 *   make CC=clang \
 *        CFLAGS="-g -O1 -fsanitize=address,fuzzer-no-link" \
 *        LDFLAGS="-g -fsanitize=address -fsanitize=fuzzer" \
 *        FUZZER_DRIVER="" \
 *        mostly_clean oss_fuzz_dhcp6
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

/*
 * get_client_mac() is defined in dhcp6.c and loops up to 5× with 100ms
 * nanosleep() per iteration waiting for a neighbour-cache entry, giving
 * ~500ms per fuzzer execution (~2 exec/s).  Return a fixed fake MAC instead
 * so the fuzzer runs at full throughput.
 */
void get_client_mac(struct in6_addr *client, int iface,
                    unsigned char *mac, unsigned int *maclenp,
                    unsigned int *mactypep, time_t now)
{
  (void)client; (void)iface; (void)now;
  memcpy(mac, "\xde\xad\xbe\xef\x00\x02", 6);
  *maclenp  = 6;
  *mactypep = ARPHRD_ETHER;
}

/* Synthetic DUID-LL (type 3, hw_type 1=Ethernet, MAC de:ad:be:ef:00:01) */
static unsigned char synthetic_duid[] = {
  0x00, 0x03,               /* DUID type 3 = DUID-LL */
  0x00, 0x01,               /* hw_type 1 = Ethernet  */
  0xde, 0xad, 0xbe, 0xef, 0x00, 0x01  /* MAC address */
};

/* ── Context chain setup ──────────────────────────────────────────────── */
/*
 * Replicates the relevant part of the static complete_context6() in dhcp6.c,
 * without requiring iface_enumerate() or netlink.  Must be called before each
 * dhcp6_reply() invocation so that context->current is rebuilt from scratch.
 *
 * local — the global unicast address we inject for the loopback interface.
 *         fd00::1 is within --dhcp-range=fd00::100,fd00::200/64.
 *
 * Returns the head of the linked context chain (passed to dhcp6_reply() as
 * the first argument), or NULL if no contexts matched.
 */
static struct dhcp_context *build_context6_chain(const struct in6_addr *local)
{
  struct dhcp_context *ctx, *chain = NULL;

  /* Reset all contexts to the "unlinked" state (current == self, local6 = 0) */
  for (ctx = daemon->dhcp6; ctx; ctx = ctx->next)
    {
      ctx->current = ctx;
      memset(&ctx->local6, 0, IN6ADDRSZ);
    }

  for (ctx = daemon->dhcp6; ctx; ctx = ctx->next)
    {
      if (!(ctx->flags & CONTEXT_DHCP))
        continue;
      if (ctx->flags & (CONTEXT_TEMPLATE | CONTEXT_OLD))
        continue;
      if (ctx->current != ctx)  /* already linked into another chain */
        continue;

      if (is_same_net6(local, &ctx->start6, ctx->prefix) &&
          is_same_net6(local, &ctx->end6,   ctx->prefix))
        {
          ctx->local6    = *local;
          ctx->preferred = 0xffffffff;
          ctx->valid     = 0xffffffff;
          /* insert at head — ordering by preferred time not critical for fuzzing */
          ctx->current   = chain;
          chain          = ctx;
        }
    }

  return chain;
}

/* ── One-time initialization ─────────────────────────────────────────── */
int LLVMFuzzerInitialize(int *argc, char ***argv)
{
  (void)argc; (void)argv;

  static char *fuzz_argv[] = {
    "fuzz_dhcp6_reply",
    "--no-daemon",
    "--no-resolv",
    "--no-hosts",
    "--port=0",
    "--interface=lo",
    /*
     * Primary DHCPv6 pool on fd00::/64 (ULA).  The harness injects fd00::1
     * as the local address, which falls within this prefix, so
     * build_context6_chain() will link this context.
     */
    "--dhcp-range=fd00::100,fd00::200,64,12h",
    "--dhcp-authoritative",
    /*
     * Pre-configured host so find_config() CLID path is reachable.
     * DUID-LL de:ad:be:ef:00:01 matches the seed lease set up per-input.
     */
    "--dhcp-host=id:00:03:00:01:de:ad:be:ef:00:01,fd00::150,testhost6",
    /*
     * Relay: local=fd00::1, server=fd00::ffff.
     * relay->iface_index is patched to lo after dhcp6_init() below.
     * relay_upstream6() fires for client requests when iface_index matches.
     * relay_reply6() fires when msg_type==DHCP6RELAYREPL and
     * link_addr==fd00::1.
     */
    "--dhcp-relay=fd00::1,fd00::ffff",
    /*
     * OPT_LOG_OPTS → log_options() and all option_bool(OPT_LOG_OPTS) branches
     * in rfc3315.c.  Absorbed by /dev/null to avoid I/O noise.
     */
    "--log-dhcp",
    /* discard lease file writes to avoid file-I/O non-determinism */
    "--dhcp-leasefile=/dev/null",
    "--log-facility=/dev/null",
  };
  int fuzz_argc = (int)(sizeof(fuzz_argv) / sizeof(fuzz_argv[0]));

  read_opts(fuzz_argc, fuzz_argv, "");

  /* mirror dnsmasq.c initialisation that read_opts skips */
  daemon->dumpfd  = -1;
  daemon->icmp6fd = -1;  /* prevents the 500ms sleep in get_client_mac fallback */

  if (daemon->edns_pktsz < PACKETSZ)
    daemon->edns_pktsz = PACKETSZ;
  daemon->packet_buff_sz = daemon->edns_pktsz + MAXDNAME + RRFIXEDSZ;
  daemon->packet = safe_malloc(daemon->packet_buff_sz);

  /*
   * dnsmasq.c:main() sets doing_dhcp6 by walking daemon->dhcp6 contexts;
   * read_opts() populates the contexts but never sets the flag.
   */
  {
    struct dhcp_context *ctx;
    for (ctx = daemon->dhcp6; ctx; ctx = ctx->next)
      if (ctx->flags & CONTEXT_DHCP)
        daemon->doing_dhcp6 = 1;
  }

  /* Provide a synthetic DUID so lease_init() doesn't die() */
  daemon->duid     = synthetic_duid;
  daemon->duid_len = sizeof(synthetic_duid);

  dhcp_common_init();
  lease_init(FUZZ_NOW);
  dhcp6_init();   /* binds daemon->dhcp6fd to DHCPV6_SERVER_PORT (547) */

  /*
   * Rebind daemon->dhcp6fd to port 0 so that multiple parallel harness
   * instances (e.g. main + ASAN secondary) can coexist on the same host.
   * The socket is only used by relay_upstream6() for sendto() calls which
   * fail gracefully when no relay server is reachable.
   */
  {
    struct sockaddr_in6 sa;
    close(daemon->dhcp6fd);
    daemon->dhcp6fd = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (daemon->dhcp6fd == -1)
      {
        perror("harness: socket");
        return 1;
      }
    memset(&sa, 0, sizeof(sa));
#ifdef HAVE_SOCKADDR_SA_LEN
    sa.sin6_len = sizeof(sa);
#endif
    sa.sin6_family = AF_INET6;
    sa.sin6_addr   = in6addr_any;
    sa.sin6_port   = 0;   /* let the OS pick an ephemeral port */
    if (bind(daemon->dhcp6fd, (struct sockaddr *)&sa, sizeof(sa)) == -1)
      {
        perror("harness: bind port 0");
        return 1;
      }
  }

  /*
   * Enable lease_change_command paths in add_address()
   * (OPTION6_VENDOR_CLASS, OPTION6_ORO, OPTION6_MUD_URL,
   *  OPTION6_USER_CLASS parsing + lease_add_extradata).
   * Must be set AFTER lease_init() — lease_init() calls popen(script+" init")
   * if the command is set, which would die() on a non-executable path.
   * daemon->helperfd is -1 so lease_update_file() never sends data to a helper.
   */
  daemon->lease_change_command = (char *)"/dev/null";

  /*
   * Patch relay6 iface_index to the loopback interface.
   * read_opts() leaves iface_index=0; without this, relay_upstream6()
   * always returns 0 (no matching relay).
   */
  {
    int lo_idx = (int)if_nametoindex("lo");
    struct dhcp_relay *r;
    for (r = daemon->relay6; r; r = r->next)
      if (r->iface_index == 0)
        r->iface_index = lo_idx;
  }

  return 0;
}

/* ── Per-input processing ────────────────────────────────────────────── */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  /* DHCPv6 minimum: msg-type (1 byte) + transaction-id (3 bytes) */
  if (size < 4)
    return 0;

  /* Inject fuzz data directly into the shared DHCPv6 packet buffer */
  if (!expand_buf(&daemon->dhcp_packet, size))
    return 0;
  memcpy(daemon->dhcp_packet.iov_base, data, size);

  int iface_index = (int)if_nametoindex("lo");
  if (iface_index == 0)
    return 0;

  /*
   * Synthetic addresses used throughout:
   *   local6       — global unicast on lo, within fd00::/64 dhcp-range
   *   ll_addr6     — link-local on lo (fe80::1)
   *   ula_addr6    — ULA on lo (zeroed: none configured)
   *   client_addr  — simulated client link-local source address
   */
  struct in6_addr local6, ll_addr6, ula_addr6, client_addr;
  inet_pton(AF_INET6, "fd00::1", &local6);
  inet_pton(AF_INET6, "fe80::1", &ll_addr6);
  inet_pton(AF_INET6, "fe80::2", &client_addr);
  memset(&ula_addr6, 0, sizeof(ula_addr6));

  /*
   * Pre-create a DHCPv6 NA lease for the known DUID host so that
   * RENEW/REBIND/RELEASE/CONFIRM paths (which require an existing lease)
   * are reachable without organically discovering a SOLICIT→REPLY exchange.
   *
   * lease6_allocate() returns NULL if a lease already exists (harmless —
   * lease_prune() cleans up at the end of each input).
   */
  {
    struct in6_addr seed_addr;
    inet_pton(AF_INET6, "fd00::150", &seed_addr);
    struct dhcp_lease *seed_lease = lease6_allocate(&seed_addr, LEASE_NA);
    if (seed_lease)
      {
        static const unsigned char seed_clid[] = {
          0x00, 0x03, 0x00, 0x01,
          0xde, 0xad, 0xbe, 0xef, 0x00, 0x01
        };
        lease_set_hwaddr(seed_lease, NULL, seed_clid, 0, 0,
                         sizeof(seed_clid), FUZZ_NOW, 0);
        lease_set_expires(seed_lease, 43200, FUZZ_NOW);
        lease_set_interface(seed_lease, iface_index, FUZZ_NOW);
        lease_set_iaid(seed_lease, 1); /* match corpus seeds; RELEASE/DECLINE check iaid */
      }
  }

  /* Reset per-iteration relay matchcounts (mirrors dhcp6_packet()) */
  {
    struct dhcp_relay *r;
    for (r = daemon->relay6; r; r = r->next)
      r->matchcount = 0;
  }

  /*
   * relay_reply6() — rfc3315.c
   *
   * Returns non-zero when the packet is a DHCP6RELAYREPL (0x13) from an
   * upstream server to be forwarded back to a client via us as relay.
   * Guards: sz >= 38 && *inbuff == DHCP6RELAYREPL &&
   *         link_address (bytes[2..17]) matches relay->local.addr6.
   *
   * Mirrors dhcp6_packet() line 213.
   */
  {
    struct sockaddr_in6 peer;
    memset(&peer, 0, sizeof(peer));
#ifdef HAVE_SOCKADDR_SA_LEN
    peer.sin6_len = sizeof(peer);
#endif
    peer.sin6_family   = AF_INET6;
    peer.sin6_addr     = client_addr;
    peer.sin6_scope_id = (uint32_t)iface_index;

    if (relay_reply6(&peer, (ssize_t)size, "lo") != 0)
      goto done;
  }

  /*
   * relay_upstream6() — rfc3315.c
   *
   * Wraps a client request in DHCP6RELAYFORW and forwards it to the upstream
   * server.  Only acts when a relay6 entry exists with a matching iface_index.
   * The actual sendto() to fd00::ffff will fail gracefully (no server there).
   *
   * Mirrors dhcp6_packet() line 297.
   */
  relay_upstream6(iface_index, (ssize_t)size, &client_addr,
                  (u32)iface_index, FUZZ_NOW);

  /* Build the DHCPv6 context chain for fd00::/64 */
  {
    struct dhcp_context *ctx = build_context6_chain(&local6);
    if (!ctx)
      goto done;

    /* Prune expired leases before processing */
    lease_prune(NULL, FUZZ_NOW);

    /*
     * dhcp6_reply() returns the port to reply on (non-zero on success).
     * We ignore it — no socket to send on.
     *
     * multicast_dest=1 bypasses the early guard at rfc3315.c:85:
     *   if (msg_type != DHCP6RELAYFORW && !multicast_dest) return 0;
     * This allows all DHCPv6 message types to be processed.
     */
    dhcp6_reply(ctx, /*multicast_dest=*/1, iface_index, "lo",
                &local6, &ll_addr6, &ula_addr6,
                size, &client_addr, FUZZ_NOW);
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
