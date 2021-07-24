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

int SecmodInMsg_CB(struct snmp_secmod_incoming_params *sp1) {
    return SNMPERR_SUCCESS;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    oid *root = malloc(MAX_OID_LEN * sizeof(oid));
    size_t rootlen;
    char *input;

    input = strndup((const char *)data, size);
    snmp_parse_oid((const char *)input, root, &rootlen);
    free(root);
    free(input);
    return 0; 
}
