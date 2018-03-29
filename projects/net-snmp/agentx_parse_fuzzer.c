#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
// We build with the agentx dir in an -I
#include <protocol.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    /*
     * Turn on all debugging, to help understand what
     * bits of the parser are running.
     */
#if 0
    snmp_enable_stderrlog();
    snmp_set_do_debugging(1);
    debug_register_tokens("");
#endif
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    unsigned char *data_ptr = (unsigned char *)calloc(1, size);
    netsnmp_pdu *pdu = SNMP_MALLOC_TYPEDEF(netsnmp_pdu);
    netsnmp_session session;

    session.version = AGENTX_VERSION_1;
    memcpy(data_ptr, data, size);
    agentx_parse(&session, pdu, data_ptr, size);
    snmp_free_pdu(pdu);
    free(data_ptr);
    return 0;
}


