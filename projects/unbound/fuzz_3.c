#include "config.h"
#include "sldns/sbuffer.h"
#include "sldns/wire2str.h"
#include "sldns/str2wire.h"
#include "util/data/dname.h"

#define SZ 1000
#define SZ2 100


int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t nr) {
  char *bin = malloc(nr);
  uint8_t *bout;
  size_t len, len2;

  memset(bin, 0, nr);
  memcpy(bin, buf, nr);

  if (nr > 2) {
    bin[nr-1] = 0x00;  // null terminate
    len = bin[0] & 0xff;  // want random sized output buf
    bout = malloc(len);
    nr--;
    bin++;
  
    // call the targets  
    len2 = len; sldns_str2wire_dname_buf(bin, bout, &len2);
    len2 = len; sldns_str2wire_int8_buf(bin, bout, &len2);
    len2 = len; sldns_str2wire_int16_buf(bin, bout, &len2);
    len2 = len; sldns_str2wire_int32_buf(bin, bout, &len2);
    len2 = len; sldns_str2wire_a_buf(bin, bout, &len2);
    len2 = len; sldns_str2wire_aaaa_buf(bin, bout, &len2);
    len2 = len; sldns_str2wire_str_buf(bin, bout, &len2);
    len2 = len; sldns_str2wire_apl_buf(bin, bout, &len2);
    len2 = len; sldns_str2wire_b64_buf(bin, bout, &len2);
    len2 = len; sldns_str2wire_b32_ext_buf(bin, bout, &len2);
    len2 = len; sldns_str2wire_hex_buf(bin, bout, &len2);
    len2 = len; sldns_str2wire_nsec_buf(bin, bout, &len2);
    len2 = len; sldns_str2wire_type_buf(bin, bout, &len2);
    len2 = len; sldns_str2wire_class_buf(bin, bout, &len2);
    len2 = len; sldns_str2wire_cert_alg_buf(bin, bout, &len2);
    len2 = len; sldns_str2wire_alg_buf(bin, bout, &len2);
    len2 = len; sldns_str2wire_tsigerror_buf(bin, bout, &len2);
    len2 = len; sldns_str2wire_time_buf(bin, bout, &len2);
    len2 = len; sldns_str2wire_tsigtime_buf(bin, bout, &len2);
    len2 = len; sldns_str2wire_period_buf(bin, bout, &len2);
    len2 = len; sldns_str2wire_loc_buf(bin, bout, &len2);
    len2 = len; sldns_str2wire_wks_buf(bin, bout, &len2);
    len2 = len; sldns_str2wire_nsap_buf(bin, bout, &len2);
    len2 = len; sldns_str2wire_atma_buf(bin, bout, &len2);
    len2 = len; sldns_str2wire_ipseckey_buf(bin, bout, &len2);
    len2 = len; sldns_str2wire_nsec3_salt_buf(bin, bout, &len2);
    len2 = len; sldns_str2wire_ilnp64_buf(bin, bout, &len2);
    len2 = len; sldns_str2wire_eui48_buf(bin, bout, &len2);
    len2 = len; sldns_str2wire_eui64_buf(bin, bout, &len2);
    len2 = len; sldns_str2wire_tag_buf(bin, bout, &len2);
    len2 = len; sldns_str2wire_long_str_buf(bin, bout, &len2);
    len2 = len; sldns_str2wire_hip_buf(bin, bout, &len2);
    len2 = len; sldns_str2wire_int16_data_buf(bin, bout, &len2);

    bin--;
    free(bout);
  }

out:
  free(bin);
}
