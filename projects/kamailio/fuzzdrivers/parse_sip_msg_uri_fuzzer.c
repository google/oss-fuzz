#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "hf.h"
#include "keys.h"
#include "msg_parser.h"
#include "parse_addr_spec.h"
#include "parse_allow.h"
#include "parse_body.h"
#include "parse_content.h"
#include "parse_cseq.h"
#include "parse_date.h"
#include "parse_def.h"
#include "parse_disposition.h"
#include "parse_diversion.h"
#include "parse_event.h"
#include "parse_expires.h"
#include "parse_fline.h"
#include "parse_from.h"
#include "parse_hname2.h"
#include "parse_identity.h"
#include "parse_identityinfo.h"
#include "parse_methods.h"
#include "parse_nameaddr.h"
#include "parse_option_tags.h"
#include "parse_param.h"
#include "parse_ppi_pai.h"
#include "parse_privacy.h"
#include "parse_refer_to.h"
#include "parse_require.h"
#include "parse_retry_after.h"
#include "parse_rpid.h"
#include "parse_rr.h"
#include "parse_sipifmatch.h"
#include "parse_subscription_state.h"
#include "parse_supported.h"
#include "parse_to.h"
#include "parse_uri.h"
#include "parse_via.h"
#include "parser_f.h"
#include "parse_uri.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    str uri;
    char *buf;
    struct sip_msg msg;

    uri.s = buf = (char *)malloc(Size + 1);
    if (!buf) {
        return 0;
    }
    memcpy(uri.s, Data, Size);
    uri.s[Size] = '\0';
    uri.len = Size;

    memset(&msg, 0, sizeof(msg));
    msg.buf = uri.s;
    msg.len = uri.len;
    msg.first_line.type = SIP_REQUEST;
    msg.first_line.u.request.method_value = METHOD_INVITE;
    msg.first_line.u.request.method.s = "INVITE";
    msg.first_line.u.request.method.len = 6;
    msg.first_line.u.request.uri = uri;
    msg.unparsed = uri.s + uri.len;

    parse_sip_msg_uri(&msg);

    free(buf);
    return 0;
}
