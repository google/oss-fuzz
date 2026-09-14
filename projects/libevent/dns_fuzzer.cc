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

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <fuzzer/FuzzedDataProvider.h>

extern "C" {
#include "event2/event.h"
#include "event2/dns.h"
#include "event2/util.h"
#include "event2/dns_struct.h"
}

static void dns_callback(int result, char type, int count, int ttl, void *addresses, void *arg) {
}

static void dns_server_cb(struct evdns_server_request *req, void *data) {
    evdns_server_request_respond(req, 0);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 10) return 0;

    FuzzedDataProvider data_provider(data, size);
    uint8_t mode = data_provider.ConsumeIntegral<uint8_t>();

    struct event_base *base = event_base_new();
    if (!base) return 0;

    if (mode % 3 == 0) {
        /* Config parsing (from dns_config_fuzzer.cc) */
        uint32_t flags = data_provider.ConsumeIntegral<uint32_t>();
        std::string s1 = data_provider.ConsumeRandomLengthString();
        std::string s2 = data_provider.ConsumeRandomLengthString();

        struct evdns_base *dns = evdns_base_new(base, flags % 65537);
        if (dns) {
            char resolvFilename[50];
            sprintf(resolvFilename, "/tmp/resolv.%d", getpid());
            FILE *fp = fopen(resolvFilename, "wb");
            if (fp) {
                fwrite(s1.c_str(), s1.size(), 1, fp);
                fclose(fp);
                evdns_base_resolv_conf_parse(dns, flags % 17, resolvFilename);
                unlink(resolvFilename);
            }

            char hostsFilename[50];
            sprintf(hostsFilename, "/tmp/hosts.%d", getpid());
            fp = fopen(hostsFilename, "wb");
            if (fp) {
                fwrite(s2.c_str(), s2.size(), 1, fp);
                fclose(fp);
                evdns_base_load_hosts(dns, hostsFilename);
                unlink(hostsFilename);
            }
            evdns_base_search_ndots_set(dns, flags);
            evdns_base_search_clear(dns);
            evdns_base_clear_host_addresses(dns);
            evdns_base_free(dns, 0);
        }
    } else if (mode % 3 == 1) {
        /* Server-side request parsing (from dns_message_fuzzer.cc) */
        int fds[2];
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, fds) == 0) {
            struct evdns_server_port *port =
                evdns_add_server_port_with_base(base, fds[0], 0, dns_server_cb, nullptr);
            if (port) {
                std::vector<uint8_t> packet = data_provider.ConsumeRemainingBytes<uint8_t>();
                if (packet.size() > 0) {
                    send(fds[1], packet.data(), packet.size(), 0);
                    event_base_loop(base, EVLOOP_NONBLOCK);
                }
                evdns_close_server_port(port);
            }
            close(fds[1]);
        }
    } else {
        /* Client-side response parsing (from evdns_client_fuzzer.cc) */
        struct evdns_base *dns_base = evdns_base_new(base, 0);
        if (dns_base) {
            int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
            if (sockfd >= 0) {
                evutil_make_socket_nonblocking(sockfd);
                struct sockaddr_in sin;
                memset(&sin, 0, sizeof(sin));
                sin.sin_family = AF_INET;
                sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                sin.sin_port = 0;
                if (bind(sockfd, (struct sockaddr *)&sin, sizeof(sin)) == 0) {
                    socklen_t slen = sizeof(sin);
                    getsockname(sockfd, (struct sockaddr *)&sin, &slen);
                    char addr_port[64];
                    snprintf(addr_port, sizeof(addr_port), "127.0.0.1:%d", ntohs(sin.sin_port));
                    evdns_base_nameserver_ip_add(dns_base, addr_port);

                    uint8_t type = data_provider.ConsumeIntegral<uint8_t>() % 4;
                    const char *name = "example.com";
                    switch (type) {
                        case 0: evdns_base_resolve_ipv4(dns_base, name, 0, dns_callback, NULL); break;
                        case 1: evdns_base_resolve_ipv6(dns_base, name, 0, dns_callback, NULL); break;
                        case 2: {
                            struct in_addr addr;
                            addr.s_addr = 0x01020304;
                            evdns_base_resolve_reverse(dns_base, &addr, 0, dns_callback, NULL);
                        } break;
                        case 3: evdns_base_resolve_reverse_ipv6(dns_base, (struct in6_addr *)"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1", 0, dns_callback, NULL); break;
                    }
                    event_base_loop(base, EVLOOP_NONBLOCK);

                    struct sockaddr_in client_addr;
                    slen = sizeof(client_addr);
                    char buf[1500];
                    int n = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr *)&client_addr, &slen);
                    if (n > 0) {
                        std::vector<uint8_t> resp = data_provider.ConsumeRemainingBytes<uint8_t>();
                        if (resp.size() > 0) {
                            sendto(sockfd, resp.data(), resp.size(), 0, (struct sockaddr *)&client_addr, slen);
                            event_base_loop(base, EVLOOP_NONBLOCK);
                        }
                    }
                }
                close(sockfd);
            }
            evdns_base_free(dns_base, 0);
        }
    }

    event_base_free(base);
    return 0;
}
