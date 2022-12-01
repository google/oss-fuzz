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
    AvahiRecord* rec = avahi_dns_packet_consume_record(packet, NULL);
    if (rec) {
        avahi_record_is_valid(rec);
        char *s = avahi_record_to_string(rec);
        avahi_free(s);
        avahi_record_unref(rec);
    }
    avahi_dns_packet_free(packet);

    return 0;
}
