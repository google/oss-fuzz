/*
# Copyright 2018 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
*/
#include "dp-packet.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/ofp-print.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    struct ofpbuf b;
    if (size < sizeof(struct ofp_header)) return 0;

    ofpbuf_use_const(&b, data, size);
    for (;;) {
	struct ofp_header *oh;
	size_t length, tail_len;
	void *tail;

	// Check if ofpbuf contains ofp header
	oh = (struct ofp_header *)ofpbuf_at(&b, 0, sizeof *oh);
	if (!oh) break;

	// Check if length is geq than lower bound
	length = ntohs(oh->length);
	if (length < sizeof *oh) break;

	// Check if ofpbuf contains payload
	tail_len = length - sizeof *oh;
	tail = ofpbuf_at(&b, sizeof *oh, tail_len);
	if (!tail) break;

	ofp_print(stdout, ofpbuf_pull(&b, length), length, NULL, NULL, 2);
    }
    ofpbuf_uninit(&b);
    return 0;
}