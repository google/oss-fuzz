/*
 * utf8-fuzzer.c - Manual harness for tmux UTF-8 handling
 *
 * Target: utf8.c - all public functions
 * Fuzzes UTF-8 validation, conversion, string operations, and padding.
 *
 * UTF-8 handling bugs can lead to buffer overflows, invalid memory
 * access, or incorrect string handling.
 */

#include <assert.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "tmux.h"

#define FUZZER_MAXLEN 1024

struct event_base *libevent;

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct utf8_data ud, ud2;
    enum utf8_state  state;
    utf8_char        uc;
    char            *nullterm;
    char            *result;
    size_t           i;
    wchar_t          wc;

    if (size == 0 || size > FUZZER_MAXLEN)
        return 0;

    /* Test 1: utf8_open and utf8_append - byte-by-byte parsing */
    state = utf8_open(&ud, data[0]);
    for (i = 1; i < size && state == UTF8_MORE; i++) {
        state = utf8_append(&ud, data[i]);
    }

    /* If we got a valid sequence, test conversions */
    if (state == UTF8_DONE) {
        /* utf8_from_data / utf8_to_data round-trip */
        utf8_from_data(&ud, &uc);
        utf8_to_data(uc, &ud2);

        /* utf8_towc - wide char conversion */
        utf8_towc(&ud, &wc);

        /* utf8_copy */
        utf8_copy(&ud2, &ud);
    }

    /* Test 2: utf8_set with various byte values */
    for (i = 0; i < size && i < 8; i++) {
        utf8_set(&ud, data[i]);
    }

    /* Test 3: utf8_build_one for single-byte characters */
    for (i = 0; i < size && i < 16; i++) {
        utf8_build_one(data[i]);
    }

    /* Test 4: utf8_fromwc - convert fuzz data as wide characters */
    if (size >= 4) {
        wc = (wchar_t)((data[0] << 24) | (data[1] << 16) |
            (data[2] << 8) | data[3]);
        utf8_fromwc(wc, &ud);
    }
    if (size >= 2) {
        wc = (wchar_t)((data[0] << 8) | data[1]);
        utf8_fromwc(wc, &ud);
    }
    /* Try common Unicode ranges */
    for (i = 0; i < size && i < 4; i++) {
        utf8_fromwc((wchar_t)data[i], &ud);
    }

    /* Create null-terminated string for string-based tests */
    nullterm = malloc(size + 1);
    if (nullterm == NULL)
        return 0;
    memcpy(nullterm, data, size);
    nullterm[size] = '\0';

    /* Test 5: utf8_isvalid */
    utf8_isvalid(nullterm);

    /* Test 6: utf8_strvis */
    {
        char *visstr = malloc(size * 4 + 1);
        if (visstr != NULL) {
            utf8_strvis(visstr, nullterm, size, VIS_OCTAL | VIS_CSTYLE);
            free(visstr);
        }
    }

    /* Test 7: utf8_stravis - allocating version */
    {
        char *vis_alloc = NULL;
        utf8_stravis(&vis_alloc, nullterm, VIS_OCTAL | VIS_CSTYLE);
        free(vis_alloc);
    }

    /* Test 8: utf8_stravisx - allocating version with explicit length */
    {
        char *vis_alloc = NULL;
        utf8_stravisx(&vis_alloc, nullterm, size, VIS_OCTAL);
        free(vis_alloc);
    }

    /* Test 9: utf8_sanitize */
    {
        result = utf8_sanitize(nullterm);
        free(result);
    }

    /* Test 10: utf8_fromcstr / utf8_tocstr / utf8_strlen / utf8_strwidth */
    {
        struct utf8_data *udarray = utf8_fromcstr(nullterm);
        if (udarray != NULL) {
            size_t len = utf8_strlen(udarray);
            utf8_strwidth(udarray, -1);
            if (len > 0)
                utf8_strwidth(udarray, (ssize_t)(len / 2));
            result = utf8_tocstr(udarray);
            free(result);
            free(udarray);
        }
    }

    /* Test 11: utf8_cstrwidth */
    utf8_cstrwidth(nullterm);

    /* Test 12: utf8_padcstr - pad on the left */
    {
        u_int cwidth = utf8_cstrwidth(nullterm);
        result = utf8_padcstr(nullterm, cwidth + 5);
        free(result);
        /* Also test when width <= current width */
        if (cwidth > 0) {
            result = utf8_padcstr(nullterm, cwidth - 1);
            free(result);
        }
    }

    /* Test 13: utf8_rpadcstr - pad on the right */
    {
        u_int cwidth = utf8_cstrwidth(nullterm);
        result = utf8_rpadcstr(nullterm, cwidth + 5);
        free(result);
        if (cwidth > 0) {
            result = utf8_rpadcstr(nullterm, cwidth - 1);
            free(result);
        }
    }

    /* Test 14: utf8_cstrhas - search for character in string */
    {
        struct utf8_data search_ud;
        /* Search for first byte as a character */
        utf8_set(&search_ud, data[0]);
        utf8_cstrhas(nullterm, &search_ud);

        /* Search for a known ASCII character */
        utf8_set(&search_ud, 'a');
        utf8_cstrhas(nullterm, &search_ud);

        /* If we parsed a valid UTF-8 sequence, search for it */
        if (state == UTF8_DONE)
            utf8_cstrhas(nullterm, &ud);
    }

    /* Test 15: Parse multiple UTF-8 sequences from input */
    i = 0;
    while (i < size) {
        state = utf8_open(&ud, data[i]);
        i++;
        while (i < size && state == UTF8_MORE) {
            state = utf8_append(&ud, data[i]);
            i++;
        }
        if (state == UTF8_DONE) {
            utf8_from_data(&ud, &uc);
            utf8_to_data(uc, &ud2);
            utf8_copy(&ud2, &ud);
        }
    }

    /* Test 16: utf8_strvis with different flags */
    {
        char *visstr = malloc(size * 4 + 1);
        if (visstr != NULL) {
            utf8_strvis(visstr, nullterm, size, VIS_OCTAL);
            utf8_strvis(visstr, nullterm, size, VIS_CSTYLE);
            if (size > 0)
                utf8_strvis(visstr, nullterm, size, VIS_DQ);
            free(visstr);
        }
    }

    /* Test 17: utf8_fromwc with values from the width cache range */
    {
        /* Emoji range */
        wchar_t test_wcs[] = {
            0x0261D, 0x1F600, 0x1F385, 0x00E9, 0x4E2D,
            0x3042, 0x0041, 0x0000
        };
        for (i = 0; i < sizeof(test_wcs) / sizeof(test_wcs[0]); i++) {
            utf8_fromwc(test_wcs[i], &ud);
            if (ud.size > 0 && ud.size <= UTF8_SIZE) {
                utf8_from_data(&ud, &uc);
                utf8_to_data(uc, &ud2);
            }
        }
    }

    free(nullterm);

    return 0;
}

int
LLVMFuzzerInitialize(__unused int *argc, __unused char ***argv)
{
    const struct options_table_entry *oe;

    global_environ = environ_create();
    global_options = options_create(NULL);
    global_s_options = options_create(NULL);
    global_w_options = options_create(NULL);

    for (oe = options_table; oe->name != NULL; oe++) {
        if (oe->scope & OPTIONS_TABLE_SERVER)
            options_default(global_options, oe);
        if (oe->scope & OPTIONS_TABLE_SESSION)
            options_default(global_s_options, oe);
        if (oe->scope & OPTIONS_TABLE_WINDOW)
            options_default(global_w_options, oe);
    }

    libevent = osdep_event_init();
    socket_path = xstrdup("dummy");

    utf8_update_width_cache();

    return 0;
}
