/* Copyright 2026 Google LLC
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
/*
 * Client side of NTLM: the fuzzer plays a (possibly malicious) server.
 *
 * Input: one configuration byte (LM_COMPAT_LEVEL and the GSS flags the
 * client asks for), then tokens with a 16-bit length prefix, like
 * fuzz-accept-sec-context. The first token answers the client's NEGOTIATE
 * (it is the server's CHALLENGE). If the context is established, the
 * following tokens go to unwrap and verify_mic, and the context is exported
 * and imported again.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <krb5.h>
#include <gssapi.h>
#include "gss_ntlmssp.h"

#if defined(__has_feature)
#if __has_feature(address_sanitizer)
#include <sanitizer/lsan_interface.h>
#define HAVE_LSAN 1
#endif
#endif

static gss_cred_id_t g_cred = GSS_C_NO_CREDENTIAL;
static gss_name_t g_target = GSS_C_NO_NAME;

static void setup(void)
{
    uint32_t maj, min;
    gss_name_t user = GSS_C_NO_NAME;
    gss_buffer_desc ubuf = { strlen("TESTDOM\\testuser"), "TESTDOM\\testuser" };
    gss_buffer_desc tbuf = { strlen("HTTP@server.example"), "HTTP@server.example" };
    gss_buffer_desc pwd = { strlen("testpassword"), "testpassword" };

    maj = gssntlm_import_name(&min, &ubuf, GSS_C_NT_USER_NAME, &user);
    if (maj) abort();
    maj = gssntlm_import_name(&min, &tbuf, GSS_C_NT_HOSTBASED_SERVICE, &g_target);
    if (maj) abort();
    maj = gssntlm_acquire_cred_with_password(&min, user, &pwd, GSS_C_INDEFINITE,
                                             GSS_C_NO_OID_SET, GSS_C_INITIATE,
                                             &g_cred, NULL, NULL);
    if (maj) abort();
    gssntlm_release_name(&min, &user);
}

/* One full in-process handshake, so that the library's one-time global
 * state (the OpenSSL 3 legacy provider context, freed only at exit) is
 * created before fuzzing starts and is not reported as a per-input leak. */
static void warm_up(void)
{
    uint32_t maj, min;
    gss_ctx_id_t c = GSS_C_NO_CONTEXT, s = GSS_C_NO_CONTEXT;
    gss_buffer_desc neg = GSS_C_EMPTY_BUFFER, chal = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc auth = GSS_C_EMPTY_BUFFER;

    maj = gssntlm_init_sec_context(&min, g_cred, &c, g_target, GSS_C_NO_OID,
                                   GSS_C_INTEG_FLAG | GSS_C_CONF_FLAG, 0,
                                   GSS_C_NO_CHANNEL_BINDINGS, GSS_C_NO_BUFFER,
                                   NULL, &neg, NULL, NULL);
    if (maj == GSS_S_CONTINUE_NEEDED) {
        maj = gssntlm_accept_sec_context(&min, &s, GSS_C_NO_CREDENTIAL, &neg,
                                         GSS_C_NO_CHANNEL_BINDINGS, NULL,
                                         NULL, &chal, NULL, NULL, NULL);
    }
    if (maj == GSS_S_CONTINUE_NEEDED) {
        gssntlm_init_sec_context(&min, g_cred, &c, g_target, GSS_C_NO_OID,
                                 GSS_C_INTEG_FLAG | GSS_C_CONF_FLAG, 0,
                                 GSS_C_NO_CHANNEL_BINDINGS, &chal, NULL,
                                 &auth, NULL, NULL);
    }
    gss_release_buffer(&min, &neg);
    gss_release_buffer(&min, &chal);
    gss_release_buffer(&min, &auth);
    gssntlm_delete_sec_context(&min, &c, GSS_C_NO_BUFFER);
    gssntlm_delete_sec_context(&min, &s, GSS_C_NO_BUFFER);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
#ifdef HAVE_LSAN
    /* one-time process state (credentials, OpenSSL legacy provider used
     * for MD4); the library frees the provider context only at exit */
    __lsan_disable();
#endif
    setup();
    warm_up();
#ifdef HAVE_LSAN
    __lsan_enable();
#endif
    return 0;
}

static int next_token(const uint8_t **data, size_t *size, gss_buffer_desc *tok)
{
    uint16_t len;

    if (*size < sizeof(len)) return 0;
    memcpy(&len, *data, sizeof(len));
    *data += sizeof(len);
    *size -= sizeof(len);
    /* like the existing fuzzer, empty tokens end the input
     * (gss_release_buffer() does not free zero-length buffers) */
    if (len == 0 || len > *size) return 0;
    tok->length = len;
    tok->value = malloc(len);
    if (!tok->value) return 0;
    memcpy(tok->value, *data, len);
    *data += len;
    *size -= len;
    return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const char *levels[] = { "0", "1", "2", "3", "4", "5" };
    uint32_t maj = GSS_S_FAILURE, min;
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    gss_buffer_desc in = GSS_C_EMPTY_BUFFER;
    gss_buffer_t inp = GSS_C_NO_BUFFER;
    uint32_t flags = 0;
    uint8_t cfg;
    int round;

    if (size < 1) return 0;
    cfg = data[0];
    data++;
    size--;

    setenv("LM_COMPAT_LEVEL", levels[cfg % 6], 1);
    if (cfg & 0x08) flags |= GSS_C_INTEG_FLAG;
    if (cfg & 0x10) flags |= GSS_C_CONF_FLAG;
    if (cfg & 0x20) flags |= GSS_C_DATAGRAM_FLAG;
    if (cfg & 0x40) flags |= GSS_C_IDENTIFY_FLAG;
    if (cfg & 0x80) flags |= GSS_C_SEQUENCE_FLAG | GSS_C_REPLAY_FLAG;

    for (round = 0; round < 3; round++) {
        gss_buffer_desc out = GSS_C_EMPTY_BUFFER;

        maj = gssntlm_init_sec_context(&min, g_cred, &ctx, g_target,
                                       GSS_C_NO_OID, flags, 0,
                                       GSS_C_NO_CHANNEL_BINDINGS, inp,
                                       NULL, &out, NULL, NULL);
        gss_release_buffer(&min, &out);
        if (inp) {
            gss_release_buffer(&min, &in);
            inp = GSS_C_NO_BUFFER;
        }
        if (maj != GSS_S_CONTINUE_NEEDED) break;
        if (!next_token(&data, &size, &in)) break;
        inp = &in;
    }
    if (inp) {
        /* loop ended with a token still pending */
        gss_release_buffer(&min, &in);
        inp = GSS_C_NO_BUFFER;
    }

    if (maj == GSS_S_COMPLETE && ctx != GSS_C_NO_CONTEXT) {
        gss_buffer_desc msg = { 4, "test" };
        gss_buffer_desc tok, out;
        int i;

        /* our own direction */
        out.length = 0; out.value = NULL;
        gssntlm_wrap(&min, ctx, 1, 0, &msg, NULL, &out);
        gss_release_buffer(&min, &out);
        gssntlm_get_mic(&min, ctx, 0, &msg, &out);
        gss_release_buffer(&min, &out);

        /* attacker-controlled direction */
        for (i = 0; i < 4 && next_token(&data, &size, &tok); i++) {
            out.length = 0; out.value = NULL;
            if (i % 2 == 0) {
                gssntlm_unwrap(&min, ctx, &tok, &out, NULL, NULL);
            } else {
                gssntlm_verify_mic(&min, ctx, &msg, &tok, NULL);
            }
            gss_release_buffer(&min, &out);
            gss_release_buffer(&min, &tok);
        }

        /* serialize round trip of a real, established context */
        {
            gss_buffer_desc exp = GSS_C_EMPTY_BUFFER;
            gss_ctx_id_t ctx2 = GSS_C_NO_CONTEXT;

            if (gssntlm_export_sec_context(&min, &ctx, &exp) == GSS_S_COMPLETE) {
                if (gssntlm_import_sec_context(&min, &exp, &ctx2) == GSS_S_COMPLETE) {
                    gssntlm_delete_sec_context(&min, &ctx2, GSS_C_NO_BUFFER);
                }
            }
            gss_release_buffer(&min, &exp);
        }
    }

    gssntlm_delete_sec_context(&min, &ctx, GSS_C_NO_BUFFER);
    return 0;
}
