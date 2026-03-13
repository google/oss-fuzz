/* Copyright 2021 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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
	regional_free_all(region);
	return 0;
}
