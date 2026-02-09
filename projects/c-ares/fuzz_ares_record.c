/* Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <ares.h>

/*
 * Fuzz c-ares DNS record construction and manipulation APIs.
 * The existing fuzzers parse DNS messages but never construct them from scratch.
 * This exercises the record builder, query manipulation, and write paths.
 *
 * Functions targeted:
 *   - ares_dns_record_create()
 *   - ares_dns_record_query_add() / query_set_name() / query_set_type()
 *   - ares_dns_record_rr_add() + all RR setter functions
 *   - ares_dns_write() (serialization)
 *   - ares_dns_record_duplicate()
 *   - ares_dns_pton() / ares_dns_addr_to_ptr()
 *   - Various ares_dns_*_tostr() functions
 */

/* Helper to safely extract a null-terminated string from fuzz data */
static size_t extract_string(const uint8_t *data, size_t size,
                             char *out, size_t max_len) {
  size_t len = size < max_len ? size : max_len;
  memcpy(out, data, len);
  out[len] = '\0';
  return len;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 8) {
    return 0;
  }

  uint8_t mode = data[0] % 4;
  const uint8_t *payload = data + 1;
  size_t payload_size = size - 1;

  ares_library_init(ARES_LIB_INIT_ALL);

  switch (mode) {
    case 0: {
      /* Build a DNS query record from scratch, write it, then parse it back */
      if (payload_size < 7) break;

      unsigned short id = (payload[0] << 8) | payload[1];
      unsigned short flags = payload[2] & 0x7F; /* valid flags subset */
      ares_dns_opcode_t opcode = payload[3] % 6;
      ares_dns_rcode_t rcode = ARES_RCODE_NOERROR;

      /* Record type and class for the query */
      ares_dns_rec_type_t qtype;
      switch (payload[4] % 8) {
        case 0: qtype = ARES_REC_TYPE_A;     break;
        case 1: qtype = ARES_REC_TYPE_AAAA;  break;
        case 2: qtype = ARES_REC_TYPE_MX;    break;
        case 3: qtype = ARES_REC_TYPE_NS;    break;
        case 4: qtype = ARES_REC_TYPE_PTR;   break;
        case 5: qtype = ARES_REC_TYPE_SRV;   break;
        case 6: qtype = ARES_REC_TYPE_TXT;   break;
        default: qtype = ARES_REC_TYPE_ANY;  break;
      }
      ares_dns_class_t qclass = (payload[5] & 1) ? ARES_CLASS_IN : ARES_CLASS_ANY;

      /* Extract query name from remaining payload */
      char qname[256];
      extract_string(payload + 6, payload_size - 6, qname, 255);

      /* Create the record */
      ares_dns_record_t *dnsrec = NULL;
      ares_status_t status = ares_dns_record_create(&dnsrec, id, flags, opcode, rcode);
      if (status != ARES_SUCCESS) break;

      /* Add a query */
      ares_dns_record_query_add(dnsrec, qname, qtype, qclass);

      /* Read back query count and info */
      size_t qcnt = ares_dns_record_query_cnt(dnsrec);
      for (size_t i = 0; i < qcnt; i++) {
        const char *name = NULL;
        ares_dns_rec_type_t rtype;
        ares_dns_class_t rclass;
        ares_dns_record_query_get(dnsrec, i, &name, &rtype, &rclass);
      }

      /* Get record metadata */
      (void)ares_dns_record_get_id(dnsrec);
      (void)ares_dns_record_get_flags(dnsrec);
      (void)ares_dns_record_get_opcode(dnsrec);
      (void)ares_dns_record_get_rcode(dnsrec);

      /* Try to modify the query */
      if (qcnt > 0 && payload_size > 10) {
        char newname[128];
        extract_string(payload + 6, payload_size > 70 ? 64 : payload_size - 6,
                       newname, 127);
        ares_dns_record_query_set_name(dnsrec, 0, newname);
        ares_dns_record_query_set_type(dnsrec, 0, ARES_REC_TYPE_AAAA);
      }

      /* Serialize the record */
      unsigned char *buf = NULL;
      size_t buf_len = 0;
      if (ares_dns_write(dnsrec, &buf, &buf_len) == ARES_SUCCESS) {
        /* Parse it back */
        ares_dns_record_t *parsed = NULL;
        if (ares_dns_parse(buf, buf_len, 0, &parsed) == ARES_SUCCESS) {
          ares_dns_record_destroy(parsed);
        }
        ares_free_string(buf);
      }

      /* Exercise ares_dns_record_duplicate */
      ares_dns_record_t *dup = ares_dns_record_duplicate(dnsrec);
      if (dup) {
        ares_dns_record_destroy(dup);
      }

      ares_dns_record_destroy(dnsrec);
      break;
    }

    case 1: {
      /* Build a DNS response record with answer RRs */
      if (payload_size < 12) break;

      unsigned short id = (payload[0] << 8) | payload[1];
      unsigned short flags = ARES_FLAG_QR | ARES_FLAG_RD | ARES_FLAG_RA;

      ares_dns_record_t *dnsrec = NULL;
      if (ares_dns_record_create(&dnsrec, id, flags,
                                  ARES_OPCODE_QUERY, ARES_RCODE_NOERROR) != ARES_SUCCESS)
        break;

      /* Add a query for context */
      char qname[128];
      size_t name_end = extract_string(payload + 2, payload_size > 66 ? 64 : payload_size - 2,
                                       qname, 127);

      ares_dns_record_query_add(dnsrec, qname, ARES_REC_TYPE_A, ARES_CLASS_IN);

      /* Add an A record answer */
      ares_dns_rr_t *rr = NULL;
      if (ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ANSWER,
                                  qname, ARES_REC_TYPE_A, ARES_CLASS_IN,
                                  300) == ARES_SUCCESS && rr) {
        struct in_addr addr4;
        if (payload_size >= name_end + 6) {
          memcpy(&addr4, payload + 2 + name_end, 4);
        } else {
          addr4.s_addr = 0x0100007F; /* 127.0.0.1 */
        }
        ares_dns_rr_set_addr(rr, ARES_RR_A_ADDR, &addr4);
      }

      /* Try adding a TXT record */
      ares_dns_rr_t *txt_rr = NULL;
      if (ares_dns_record_rr_add(&txt_rr, dnsrec, ARES_SECTION_ANSWER,
                                  qname, ARES_REC_TYPE_TXT, ARES_CLASS_IN,
                                  300) == ARES_SUCCESS && txt_rr) {
        /* Add TXT data */
        size_t txt_start = 2 + name_end;
        if (txt_start < payload_size) {
          size_t txt_len = payload_size - txt_start;
          if (txt_len > 255) txt_len = 255;
          ares_dns_rr_add_abin(txt_rr, ARES_RR_TXT_DATA,
                               payload + txt_start, txt_len);
        }
      }

      /* Inspect RR counts for each section */
      (void)ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ANSWER);
      (void)ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_AUTHORITY);
      (void)ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ADDITIONAL);

      /* Get writable and const RR references */
      size_t ans_cnt = ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ANSWER);
      for (size_t i = 0; i < ans_cnt; i++) {
        const ares_dns_rr_t *crr = ares_dns_record_rr_get_const(dnsrec, ARES_SECTION_ANSWER, i);
        if (crr) {
          (void)ares_dns_rr_get_name(crr);
          (void)ares_dns_rr_get_type(crr);
          (void)ares_dns_rr_get_class(crr);
          (void)ares_dns_rr_get_ttl(crr);
        }
      }

      /* Serialize */
      unsigned char *buf = NULL;
      size_t buf_len = 0;
      if (ares_dns_write(dnsrec, &buf, &buf_len) == ARES_SUCCESS) {
        ares_free_string(buf);
      }

      ares_dns_record_destroy(dnsrec);
      break;
    }

    case 2: {
      /* Fuzz ares_dns_pton and ares_dns_addr_to_ptr */
      if (payload_size < 2) break;

      char ipstr[129];
      extract_string(payload + 1, payload_size - 1, ipstr, 128);

      struct ares_addr addr;
      memset(&addr, 0, sizeof(addr));

      /* Test with AF_UNSPEC to let it auto-detect */
      addr.family = AF_UNSPEC;
      size_t out_len = 0;
      const void *result = ares_dns_pton(ipstr, &addr, &out_len);
      if (result) {
        /* Convert to PTR format */
        char *ptr_str = ares_dns_addr_to_ptr(&addr);
        if (ptr_str) {
          ares_free_string(ptr_str);
        }
      }

      /* Also try with explicit family */
      addr.family = (payload[0] & 1) ? AF_INET6 : AF_INET;
      result = ares_dns_pton(ipstr, &addr, &out_len);
      if (result) {
        char *ptr_str = ares_dns_addr_to_ptr(&addr);
        if (ptr_str) {
          ares_free_string(ptr_str);
        }
      }
      break;
    }

    case 3: {
      /* Fuzz all string-to-enum and enum-to-string conversion functions */
      /* These are used throughout the DNS record handling code */

      /* Test enum-to-string for various types */
      for (size_t i = 0; i < payload_size && i < 64; i++) {
        uint16_t val = payload[i];
        if (i + 1 < payload_size) {
          val |= ((uint16_t)payload[i + 1]) << 8;
        }

        /* Record type to string */
        (void)ares_dns_rec_type_tostr((ares_dns_rec_type_t)val);

        /* Class to string */
        (void)ares_dns_class_tostr((ares_dns_class_t)(val & 0xFF));

        /* Opcode to string */
        (void)ares_dns_opcode_tostr((ares_dns_opcode_t)(val & 0x0F));

        /* Rcode to string */
        (void)ares_dns_rcode_tostr((ares_dns_rcode_t)(val & 0x1F));

        /* Section to string */
        (void)ares_dns_section_tostr((ares_dns_section_t)((val & 0x03) + 1));

        /* RR key to string */
        (void)ares_dns_rr_key_tostr((ares_dns_rr_key_t)val);

        /* RR key datatype */
        (void)ares_dns_rr_key_datatype((ares_dns_rr_key_t)val);

        /* RR key to record type */
        (void)ares_dns_rr_key_to_rec_type((ares_dns_rr_key_t)val);

        i++; /* consume the second byte */
      }

      /* Test RR key enumeration for each record type */
      ares_dns_rec_type_t types[] = {
        ARES_REC_TYPE_A, ARES_REC_TYPE_NS, ARES_REC_TYPE_CNAME,
        ARES_REC_TYPE_SOA, ARES_REC_TYPE_PTR, ARES_REC_TYPE_HINFO,
        ARES_REC_TYPE_MX, ARES_REC_TYPE_TXT, ARES_REC_TYPE_SIG,
        ARES_REC_TYPE_AAAA, ARES_REC_TYPE_SRV, ARES_REC_TYPE_NAPTR,
        ARES_REC_TYPE_OPT, ARES_REC_TYPE_TLSA, ARES_REC_TYPE_SVCB,
        ARES_REC_TYPE_HTTPS, ARES_REC_TYPE_URI, ARES_REC_TYPE_CAA,
        ARES_REC_TYPE_RAW_RR
      };
      for (size_t t = 0; t < sizeof(types) / sizeof(types[0]); t++) {
        size_t cnt = 0;
        const ares_dns_rr_key_t *keys = ares_dns_rr_get_keys(types[t], &cnt);
        (void)keys;
      }

      /* Test opt get helpers */
      if (payload_size >= 4) {
        ares_dns_rr_key_t key = (ares_dns_rr_key_t)(
          (payload[0] | (payload[1] << 8)));
        unsigned short opt = (payload[2] | (payload[3] << 8));
        (void)ares_dns_opt_get_datatype(key, opt);
        (void)ares_dns_opt_get_name(key, opt);
      }

      break;
    }
  }

  ares_library_cleanup();
  return 0;
}
