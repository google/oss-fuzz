/*
 * ogg_sync_fuzzer.c
 *
 * Fuzzing harness for the libogg sync/framing layer (ogg_sync_state).
 *
 * This covers the primary attack surface for libogg when parsing untrusted
 * Ogg bitstreams from files or network streams:
 *
 *   ogg_sync_buffer()    - allocate input buffer
 *   ogg_sync_wrote()     - commit bytes to the sync engine
 *   ogg_sync_pageseek()  - seek forward to next page boundary
 *   ogg_sync_pageout()   - extract complete pages
 *   ogg_stream_pagein()  - feed a page into a logical stream
 *   ogg_stream_packetout() - extract decoded packets
 *
 * Historical vulnerabilities (e.g. CVE-2018-5146, integer overflows in
 * page size calculations) are exercised by this path.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "ogg/ogg.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    ogg_sync_state   oy;
    ogg_stream_state os;
    ogg_page         og;
    ogg_packet       op;

    ogg_sync_init(&oy);

    /* Feed fuzz data into the sync layer in variable-sized chunks */
    size_t pos = 0;
    int serial_init = 0;

    while (pos < size) {
        /* Choose chunk size: alternate between small and rest-of-input */
        size_t chunk = (pos % 2 == 0) ? 1 : (size - pos);
        if (chunk > size - pos) chunk = size - pos;

        char *buf = ogg_sync_buffer(&oy, (long)chunk);
        if (!buf) break;
        memcpy(buf, data + pos, chunk);
        ogg_sync_wrote(&oy, (long)chunk);
        pos += chunk;

        /* Try to extract pages */
        while (ogg_sync_pageout(&oy, &og) == 1) {
            if (!serial_init) {
                ogg_stream_init(&os, ogg_page_serialno(&og));
                serial_init = 1;
            }
            ogg_stream_pagein(&os, &og);

            /* Extract all packets from the page */
            while (ogg_stream_packetout(&os, &op) != 0) {
                /* Access packet data to catch OOB reads */
                if (op.bytes > 0 && op.packet) {
                    volatile uint8_t sink = op.packet[0];
                    (void)sink;
                }
            }
        }
    }

    if (serial_init) ogg_stream_clear(&os);
    ogg_sync_clear(&oy);
    return 0;
}
