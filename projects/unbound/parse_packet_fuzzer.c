#include "config.h"
#include "util/regional.h"
#include "util/fptr_wlist.h"
#include "sldns/sbuffer.h"

struct regional * region = NULL;

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
	if (!region) {
		region = regional_create();
		if (!region) {
			abort();
		}
}
	sldns_buffer pktbuf;
	sldns_buffer_init_frm_data(&pktbuf, (void*)buf, len);

	struct msg_parse prs;
	memset(&prs, 0, sizeof(prs));
	parse_packet(&pktbuf, &prs, region);
	return 0;
}
