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

#include <coap.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    coap_pdu_t *pdu = coap_pdu_init(0, 0, 0, size);
    if (!pdu) return 0;
    
    coap_pdu_parse(COAP_PROTO_UDP, data, size, pdu);
    coap_delete_pdu(pdu);
    return 0;
}
