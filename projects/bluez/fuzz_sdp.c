#include <config.h>

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>

#include "bluetooth.h"
#include "hci.h"
#include "hci_lib.h"
#include "l2cap.h"
#include "sdp.h"
#include "sdp_lib.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  int scanned = 0;
  sdp_record_t *out = NULL;
  openlog("fuzz_sdp", LOG_PERROR | LOG_PID, LOG_LOCAL0);
  out = sdp_extract_pdu(data, size, &scanned);
  if (out) {
    sdp_record_free(out);
  }
  closelog();

  return 0;
}
