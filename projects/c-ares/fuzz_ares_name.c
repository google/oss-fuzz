/* Copyright 2025 Google LLC
 * Licensed under the Apache License, Version 2.0 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <ares.h>

/*
 * Fuzz DNS name decompression, query creation, and string/name expansion.
 * These are critical parsing functions that handle DNS wire-format name
 * compression pointers and are exercised throughout DNS processing.
 *
 * Functions targeted:
 *   - ares_expand_name()
 *   - ares_expand_string()
 *   - ares_create_query()
 *   - ares_inet_pton() / ares_inet_ntop()
 */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2) {
    return 0;
  }

  /* Use first byte to select operation mode */
  uint8_t mode = data[0] % 5;
  const uint8_t *payload = data + 1;
  size_t payload_size = size - 1;

  ares_library_init(ARES_LIB_INIT_ALL);

  switch (mode) {
    case 0: {
      /* Fuzz ares_expand_name: decompress DNS names with pointer compression */
      if (payload_size < 2) break;

      /* Use the payload as a simulated DNS message buffer.
       * encoded points somewhere into the buffer (offset from byte 1). */
      size_t offset = payload[0] % payload_size;
      const unsigned char *abuf = payload;
      int alen = (int)payload_size;
      const unsigned char *encoded = payload + offset;

      char *name = NULL;
      long enclen = 0;
      int status = ares_expand_name(encoded, abuf, alen, &name, &enclen);
      if (status == ARES_SUCCESS) {
        /* Use the result to prevent optimization */
        if (name && name[0]) {
          (void)name[0];
        }
        ares_free_string(name);
      }
      break;
    }

    case 1: {
      /* Fuzz ares_expand_string: expand a length-prefixed string from DNS message */
      if (payload_size < 2) break;

      size_t offset = payload[0] % payload_size;
      const unsigned char *abuf = payload;
      int alen = (int)payload_size;
      const unsigned char *encoded = payload + offset;

      unsigned char *str = NULL;
      long enclen = 0;
      int status = ares_expand_string(encoded, abuf, alen, &str, &enclen);
      if (status == ARES_SUCCESS) {
        if (str && str[0]) {
          (void)str[0];
        }
        ares_free_string(str);
      }
      break;
    }

    case 2: {
      /* Fuzz ares_create_query with varied name strings and parameters */
      if (payload_size < 6) break;

      int dnsclass = (payload[0] % 4) + 1; /* IN, CHAOS, HESOID, NONE */
      int type = payload[1];               /* Record type */
      unsigned short id = (payload[2] << 8) | payload[3];
      int rd = payload[4] & 1;
      int max_udp_size = ((payload[4] >> 1) & 1) ? 1232 : 512;

      /* Use remaining bytes as the name, null-terminated */
      size_t name_len = payload_size - 5;
      if (name_len > 255) name_len = 255;
      char name[256];
      memcpy(name, payload + 5, name_len);
      name[name_len] = '\0';

      unsigned char *buf = NULL;
      int buflen = 0;
      int status = ares_create_query(name, dnsclass, type, id, rd,
                                     &buf, &buflen, max_udp_size);
      if (status == ARES_SUCCESS) {
        /* Try to parse what we just created to exercise round-trip */
        ares_dns_record_t *dnsrec = NULL;
        if (ares_dns_parse(buf, (size_t)buflen, 0, &dnsrec) == ARES_SUCCESS) {
          /* Read back query info */
          size_t qcnt = ares_dns_record_query_cnt(dnsrec);
          for (size_t i = 0; i < qcnt; i++) {
            const char *qname = NULL;
            ares_dns_rec_type_t qtype;
            ares_dns_class_t qclass;
            ares_dns_record_query_get(dnsrec, i, &qname, &qtype, &qclass);
          }
          ares_dns_record_destroy(dnsrec);
        }
        ares_free_string(buf);
      }
      break;
    }

    case 3: {
      /* Fuzz ares_inet_pton and ares_inet_ntop for IPv4 and IPv6 */
      if (payload_size < 2) break;

      /* Null-terminate the input as an IP address string */
      size_t str_len = payload_size - 1;
      if (str_len > 128) str_len = 128;
      char ipstr[129];
      memcpy(ipstr, payload + 1, str_len);
      ipstr[str_len] = '\0';

      int af = (payload[0] & 1) ? AF_INET6 : AF_INET;

      if (af == AF_INET) {
        struct in_addr addr4;
        if (ares_inet_pton(AF_INET, ipstr, &addr4) == 1) {
          /* Round-trip: convert back to string */
          char buf[INET6_ADDRSTRLEN];
          ares_inet_ntop(AF_INET, &addr4, buf, sizeof(buf));
        }
      } else {
        struct ares_in6_addr addr6;
        if (ares_inet_pton(AF_INET6, ipstr, &addr6) == 1) {
          char buf[INET6_ADDRSTRLEN];
          ares_inet_ntop(AF_INET6, &addr6, buf, sizeof(buf));
        }
      }
      break;
    }

    case 4: {
      /* Fuzz DNS string-to-enum conversion functions */
      if (payload_size < 1) break;

      size_t str_len = payload_size;
      if (str_len > 64) str_len = 64;
      char str[65];
      memcpy(str, payload, str_len);
      str[str_len] = '\0';

      ares_dns_class_t qclass;
      ares_dns_class_fromstr(&qclass, str);

      ares_dns_rec_type_t qtype;
      ares_dns_rec_type_fromstr(&qtype, str);

      /* Also test ares_strerror with fuzzed error code */
      if (payload_size >= 2) {
        int code = (int)(int8_t)payload[0];
        const char *errstr = ares_strerror(code);
        (void)errstr;
      }
      break;
    }
  }

  ares_library_cleanup();
  return 0;
}
