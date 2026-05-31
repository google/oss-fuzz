/*
 * OSS-Fuzz harness for OpenVPN tls_pre_decrypt_lite().
 *
 * tls_pre_decrypt_lite() processes the first packet from a new client before
 * the TLS session is established. It validates the HMAC auth tag and packet
 * ID, parses the TLS control packet header, and decides whether to accept or
 * reject the connection. This is exposed to unauthenticated network input.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include "config.h"
#include "syshead.h"
#include "buffer.h"
#include "ssl_pkt.h"
#include "ssl_common.h"
#include "tls_common.h"
#include "crypto.h"
#include "error.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0;

    struct buffer buf = alloc_buf(size);
    if (!buf.data) return 0;

    buf_write(&buf, data, size);

    struct openvpn_sockaddr from;
    memset(&from, 0, sizeof(from));
    from.addr.in4.sin_family = AF_INET;

    struct tls_auth_standalone tas;
    memset(&tas, 0, sizeof(tas));

    struct tls_pre_decrypt_state state;
    memset(&state, 0, sizeof(state));

    /* tls_pre_decrypt_lite: unauthenticated path, no TLS wrap context */
    tls_pre_decrypt_lite(&tas, &state, &from, &buf);

    free_tls_pre_decrypt_state(&state);
    free_buf(&buf);
    return 0;
}
