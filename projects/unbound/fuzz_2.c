#include "config.h"
#include "sldns/sbuffer.h"
#include "sldns/wire2str.h"
#include "util/data/dname.h"

int LLVMFuzzerTestOneInput(const uint8_t *bin, size_t nr) {
  char *bout;
  uint8_t *a;
  char *b;
  size_t bl;
  size_t al;
  size_t len;

  if (nr > 2) {
    len = bin[0] & 0xff;  // want random sized output buf
    bout = malloc(len);
    nr--;
    bin++;
    b = bout; bl = len; sldns_wire2str_edns_subnet_print(&b, &bl, bin, nr);
    b = bout; bl = len; sldns_wire2str_edns_n3u_print(&b, &bl, bin, nr);
    b = bout; bl = len; sldns_wire2str_edns_dhu_print(&b, &bl, bin, nr);
    b = bout; bl = len; sldns_wire2str_edns_dau_print(&b, &bl, bin, nr);
    b = bout; bl = len; sldns_wire2str_edns_nsid_print(&b, &bl, bin, nr);
    b = bout; bl = len; sldns_wire2str_edns_ul_print(&b, &bl, bin, nr);
    b = bout; bl = len; sldns_wire2str_edns_llq_print(&b, &bl, bin, nr); 
  
    a = bin; al = nr; b = bout; bl = len; sldns_wire2str_tsigerror_scan(&a, &al, &b, &bl);
    a = bin; al = nr; b = bout; bl = len; sldns_wire2str_long_str_scan(&a, &al, &b, &bl);
    a = bin; al = nr; b = bout; bl = len; sldns_wire2str_tag_scan(&a, &al, &b, &bl);
    a = bin; al = nr; b = bout; bl = len; sldns_wire2str_eui64_scan(&a, &al, &b, &bl);
    a = bin; al = nr; b = bout; bl = len; sldns_wire2str_int16_data_scan(&a, &al, &b, &bl);
    a = bin; al = nr; b = bout; bl = len; sldns_wire2str_hip_scan(&a, &al, &b, &bl);
    a = bin; al = nr; b = bout; bl = len; sldns_wire2str_wks_scan(&a, &al, &b, &bl);
    a = bin; al = nr; b = bout; bl = len; sldns_wire2str_loc_scan(&a, &al, &b, &bl);
    a = bin; al = nr; b = bout; bl = len; sldns_wire2str_cert_alg_scan(&a, &al, &b, &bl);
    a = bin; al = nr; b = bout; bl = len; sldns_wire2str_nsec3_salt_scan(&a, &al, &b, &bl);
    a = bin; al = nr; b = bout; bl = len; sldns_wire2str_nsec_scan(&a, &al, &b, &bl);
    a = bin; al = nr; b = bout; bl = len; sldns_wire2str_b32_ext_scan(&a, &al, &b, &bl);
    a = bin; al = nr; b = bout; bl = len; sldns_wire2str_apl_scan(&a, &al, &b, &bl);
    a = bin; al = nr; b = bout; bl = len; sldns_wire2str_str_scan(&a, &al, &b, &bl);
    a = bin; al = nr; b = bout; bl = len; sldns_wire2str_rdata_unknown_scan(&a, &al, &b, &bl);
    a = bin; al = nr; b = bout; bl = len; sldns_wire2str_header_scan(&a, &al, &b, &bl);
    a = bin; al = nr; b = bout; bl = len; sldns_wire2str_pkt_scan(&a, &al, &b, &bl);

    bin--;
    free(bout);
  }

out:
  return 0;
}
