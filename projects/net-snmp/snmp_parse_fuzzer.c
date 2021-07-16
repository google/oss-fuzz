/*
 * Copyright 2021 Google LLC
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
 *
 * This fuzzer exercises the SNMP PDU parsing code, including ASN.1.
 */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    if (getenv("NETSNMP_DEBUGGING") != NULL) {
        /*
         * Turn on all debugging, to help understand what
         * bits of the parser are running.
         */
        snmp_enable_stderrlog();
        snmp_set_do_debugging(1);
        debug_register_tokens("");
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    size_t bytes_remaining = size;
    netsnmp_pdu *pdu = SNMP_MALLOC_TYPEDEF(netsnmp_pdu);

    netsnmp_session sess = { };
    snmpv3_parse(pdu, (unsigned char *)data, &bytes_remaining, NULL, &sess);
    snmp_free_pdu(pdu);
    return 0;
}
