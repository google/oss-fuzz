#include <string.h>

#include <krb5.h>
#include <gssapi.h>
#include "gss_ntlmssp.h"

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    OM_uint32 maj_stat, min_stat;

    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    gss_name_t client_name = GSS_C_NO_NAME;
    gss_cred_id_t deleg_cred = GSS_C_NO_CREDENTIAL;

    /* Each fuzz input contains multiple tokens preceded by a length field.
     * Process them in turn with gss_accept_sec_context while
     * GSS_S_CONTINUE_NEEDED is set
     */
    do {
        unsigned short token_length;

        gss_buffer_desc input_token, output_token = GSS_C_EMPTY_BUFFER;

        if (Size < sizeof(token_length))
            break;

        token_length = *(unsigned short *)Data;

        Data += sizeof(token_length);
        Size -= sizeof(token_length);

        if (token_length == 0 || token_length > Size)
            break;

        input_token.length = token_length;
        input_token.value = malloc(token_length);
        memcpy(input_token.value, Data, token_length);

        Data += token_length;
        Size -= token_length;

        maj_stat = gssntlm_accept_sec_context(
            &min_stat,
            &ctx,
            GSS_C_NO_CREDENTIAL, /* server_creds */
            &input_token,
            GSS_C_NO_CHANNEL_BINDINGS, /* input_bindings */
            &client_name,
            NULL, /* mech_type */
            &output_token,
            NULL, /* ret_flags */
            NULL, /* time */
            &deleg_cred
        );

        gss_release_buffer(&min_stat, &input_token);
        gss_release_buffer(&min_stat, &output_token);
    } while(maj_stat == GSS_S_CONTINUE_NEEDED);

    gss_release_name(&min_stat, &client_name);
    gss_release_cred(&min_stat, &deleg_cred);

    gss_delete_sec_context(&min_stat, &ctx, GSS_C_NO_BUFFER);

    return 0;
}
