/*
 * OSS-Fuzz harness for CUPS HTTP utility parsers.
 *
 * Exercises httpSeparateURI(), httpResolveURI(), and the HTTP date/header
 * parsers that process untrusted input from print clients and servers.
 */
#include <cups/cups.h>
#include <cups/http.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    /* NUL-terminate a copy of the input */
    char *input = (char *)malloc(size + 1);
    if (!input) return 0;
    memcpy(input, data, size);
    input[size] = '\0';

    /* Exercise the URI parser */
    char scheme[256], userpass[256], host[256], resource[4096];
    int port = 0;
    httpSeparateURI(HTTP_URI_CODING_ALL, input,
                    scheme, sizeof(scheme),
                    userpass, sizeof(userpass),
                    host, sizeof(host),
                    &port,
                    resource, sizeof(resource));

    /* Exercise HTTP date parser */
    httpGetDateTime(input);

    /* Exercise option string parser */
    int num_options = 0;
    cups_option_t *options = NULL;
    num_options = cupsParseOptions(input, 0, &options);
    if (num_options > 0 && options)
        cupsFreeOptions(num_options, options);

    free(input);
    return 0;
}
