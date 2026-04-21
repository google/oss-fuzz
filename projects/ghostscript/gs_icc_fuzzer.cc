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
 * Fuzzer targeting ICC profile parsing in Ghostscript.
 *
 * The existing fuzzers feed full PS/PDF/PCL documents through the GS
 * interpreter but never directly stress-test ICC profile parsing.
 * Coverage data shows gsicc_manage.c (45%), gsicc_create.c (19%),
 * gsicc_cache.c (42%), and several gsicc_*.c files at 0% coverage.
 *
 * This harness writes fuzz data as an ICC profile file and tells
 * Ghostscript to use it as the default color profile (Gray, RGB, or
 * CMYK, selected by the first byte). A small PostScript program with
 * color operations is processed to trigger ICC profile loading,
 * parsing, validation, and color conversion through the ICC pipeline.
 *
 * Attack surface: ICC profiles are embedded in untrusted PDF/PS
 * documents, making the ICC parser a high-value target for memory
 * corruption bugs.
 */

#include <base/gserrors.h>
#include <psi/iapi.h>

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* PostScript program that exercises color operations.
 * Uses gray, RGB, and CMYK color spaces to force ICC profile
 * loading and color space conversions through the ICC pipeline. */
static const char ps_program[] =
    "0.5 setgray 10 10 moveto 90 90 lineto stroke\n"
    "0.5 setgray 10 10 80 80 rectfill\n"
    "0.8 0.2 0.3 setrgbcolor 20 20 moveto 80 80 lineto stroke\n"
    "0.1 0.9 0.5 setrgbcolor 20 20 60 60 rectfill\n"
    "0.1 0.2 0.3 0.4 setcmykcolor 30 30 moveto 70 70 lineto stroke\n"
    "showpage\n";

static const unsigned char *g_data;
static size_t g_size;

static int gs_stdin(void *inst, char *buf, int len)
{
    size_t to_copy = (size_t)len < g_size ? (size_t)len : g_size;
    if (to_copy > (size_t)INT_MAX)
        to_copy = (size_t)INT_MAX;
    memcpy(buf, g_data, to_copy);
    g_data += to_copy;
    g_size -= to_copy;
    return (int)to_copy;
}

static int gs_stdnull(void *inst, const char *buf, int len)
{
    return len;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* ICC header is 128 bytes; need at least that plus selector byte */
    if (size < 129)
        return 0;

    /* First byte selects which default ICC profile to replace */
    int profile_type = data[0] % 3;
    data++;
    size--;

    /* Write fuzz data as ICC profile to temp file */
    char iccfile[256];
    sprintf(iccfile, "/tmp/fuzz_icc.%d.icc", getpid());
    FILE *f = fopen(iccfile, "wb");
    if (!f)
        return 0;
    fwrite(data, 1, size, f);
    fclose(f);

    /* Select profile argument based on type */
    char profilearg[300];
    switch (profile_type) {
        case 0:
            sprintf(profilearg, "-sDefaultGrayProfile=%s", iccfile);
            break;
        case 1:
            sprintf(profilearg, "-sDefaultRGBProfile=%s", iccfile);
            break;
        case 2:
            sprintf(profilearg, "-sDefaultCMYKProfile=%s", iccfile);
            break;
    }

    /* Set up PS program as stdin data */
    g_data = (const unsigned char *)ps_program;
    g_size = strlen(ps_program);

    void *gs = NULL;
    int ret = gsapi_new_instance(&gs, NULL);
    if (ret < 0) {
        unlink(iccfile);
        return 0;
    }

    gsapi_set_stdio(gs, gs_stdin, gs_stdnull, gs_stdnull);
    gsapi_set_arg_encoding(gs, GS_ARG_ENCODING_UTF8);

    char *args[] = {
        (char *)"gs",
        (char *)"-K1048576",
        (char *)"-dNOPAUSE",
        (char *)"-dBATCH",
        (char *)"-dQUIET",
        (char *)"-dSAFER",
        (char *)"-sDEVICE=png16m",
        (char *)"-sOutputFile=/dev/null",
        (char *)"-r72x72",
        (char *)"-dNOINTERPOLATE",
        profilearg,
        (char *)"-_",
    };
    int argc = sizeof(args) / sizeof(args[0]);

    ret = gsapi_init_with_args(gs, argc, args);
    gsapi_exit(gs);
    gsapi_delete_instance(gs);

    unlink(iccfile);
    return 0;
}
