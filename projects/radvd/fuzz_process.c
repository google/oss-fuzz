// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <net/if.h>
#include "radvd.h"

// Mock functions
int sock = -1;
int LL_DEBUG_LOG = 0;
int log_method = L_STDERR;
char *conf_file = NULL;
char *pname = "fuzz_process";

void dlog(int level, int flevel, char const *fmt, ...) {}
void flog(int level, char const *fmt, ...) {}
int get_debuglevel(void) { return 0; }

void set_debuglevel(int level) {}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < sizeof(struct icmp6_hdr)) return 0;

    struct Interface iface;
    memset(&iface, 0, sizeof(iface));
    strcpy(iface.props.name, "lo");
    iface.props.if_index = 1;
    iface.state_info.ready = 1;
    iface.AdvSendAdvert = 1;
    iface.UnicastOnly = 0;
    
    // We need to set if_addrs
    struct in6_addr addr_ll;
    memset(&addr_ll, 0, sizeof(addr_ll));
    addr_ll.s6_addr[0] = 0xfe;
    addr_ll.s6_addr[1] = 0x80;
    iface.props.if_addr = addr_ll;
    
    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    // Set link local address
    addr.sin6_addr.s6_addr[0] = 0xfe;
    addr.sin6_addr.s6_addr[1] = 0x80;

    struct in6_pktinfo pkt_info;
    memset(&pkt_info, 0, sizeof(pkt_info));
    pkt_info.ipi6_ifindex = 1;

    int hoplimit = 255;

    unsigned char *msg = (unsigned char *)malloc(size);
    memcpy(msg, data, size);

    process(sock, &iface, msg, size, &addr, &pkt_info, hoplimit);

    free(msg);
    return 0;
}
