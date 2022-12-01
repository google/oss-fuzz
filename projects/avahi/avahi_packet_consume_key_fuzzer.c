#include <stdint.h>
#include <string.h>

#include "avahi-common/malloc.h"
#include "avahi-core/dns.h"
#include "avahi-core/log.h"

void log_function(AvahiLogLevel level, const char *txt) {}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    avahi_set_log_function(log_function);
    AvahiDnsPacket* packet = avahi_dns_packet_new(size + AVAHI_DNS_PACKET_EXTRA_SIZE);
    memcpy(AVAHI_DNS_PACKET_DATA(packet), data, size);
    packet->size = size;
    AvahiKey* key = avahi_dns_packet_consume_key(packet, NULL);
    if (key) {
        avahi_key_is_valid(key);
        char *s = avahi_key_to_string(key);
        avahi_free(s);
        avahi_key_unref(key);
    }
    avahi_dns_packet_free(packet);

    return 0;
}
