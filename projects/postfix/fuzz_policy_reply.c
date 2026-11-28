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
 * Fuzz the decoding of policy server replies. smtpd(8) sends a request to
 * a policy server (a process outside Postfix) with attr_clnt_request(), and
 * reads the reply with attr_scan_plain(), expecting an "action" attribute,
 * with ATTR_FLAG_MISSING. The connection is reused for later requests, so
 * the input is read as a sequence of replies on one stream.
 *
 * Only the plain (name=value) format is fuzzed: the base64 and
 * null-terminated formats are used only between Postfix processes.
 */
#include <sys_defs.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>

#include <msg_output.h>
#include <attr.h>
#include <vstream.h>
#include <vstring.h>
#include <mail_proto.h>

/*
 * Drop informational messages and warnings: malformed input is expected
 * and would flood the log. Errors, fatal errors and panics still print.
 */
static void fuzz_msg_quiet(int level, const char *text, void *unused_context)
{
    if (level >= MSG_ERROR)
	fprintf(stderr, "%s\n", text);
}

int     LLVMFuzzerInitialize(int *argc, char ***argv);
int     LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int     LLVMFuzzerInitialize(int *argc, char ***argv)
{
    msg_output_push(fuzz_msg_quiet, (void *) 0);
    return (0);
}

#define MAX_REPLIES	16

int     LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    VSTRING *in;
    VSTREAM *fp;
    VSTRING *action;
    int     replies;

    if (size > 65536)
	return (0);
    in = vstring_alloc(size + 1);
    vstring_memcpy(in, (const char *) data, size);
    fp = vstream_memopen(in, O_RDONLY);
    action = vstring_alloc(100);

    /* One reply per request, as in smtpd_check.c:check_policy_service(). */
    for (replies = 0; replies < MAX_REPLIES; replies++)
	if (attr_scan_plain(fp, ATTR_FLAG_MISSING,
			    RECV_ATTR_STR(MAIL_ATTR_ACTION, action),
			    ATTR_TYPE_END) != 1)
	    break;

    vstring_free(action);
    (void) vstream_fclose(fp);
    vstring_free(in);
    return (0);
}
