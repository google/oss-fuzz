/*
 * utf8-llm.c - LLM-optimized harness for tmux UTF-8 handling
 *
 * Target: utf8.c (utf8_open, utf8_append, utf8_isvalid, utf8_strvis, etc.)
 *
 * LLM-generated optimizations:
 * - UTF-8 byte sequence awareness (1-4 byte sequences)
 * - Invalid/malformed UTF-8 detection
 * - Continuation byte manipulation
 * - Boundary codepoint exploration (BMP, SMP, overlong)
 * - Width calculation edge cases
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "tmux.h"
#include "compat.h"

struct event_base *libevent;

/* Declare wcwidth if not available (POSIX.1-2001) */
#ifndef wcwidth
extern int wcwidth(wchar_t wc);
#endif

#define FUZZER_MAXLEN 1024

/* Coverage hint - force distinct paths */
static void __attribute__((noinline))
coverage_hint(int path_id)
{
    volatile int x = path_id;
    (void)x;
}

/*
 * Classify UTF-8 byte for coverage guidance
 */
static int
classify_utf8_byte(uint8_t b)
{
    if (b < 0x80) {
        coverage_hint(1);  /* ASCII */
        return 1;
    } else if (b < 0xC0) {
        coverage_hint(2);  /* Continuation byte */
        return 2;
    } else if (b < 0xE0) {
        coverage_hint(3);  /* 2-byte lead */
        return 3;
    } else if (b < 0xF0) {
        coverage_hint(4);  /* 3-byte lead */
        return 4;
    } else if (b < 0xF8) {
        coverage_hint(5);  /* 4-byte lead */
        return 5;
    } else {
        coverage_hint(6);  /* Invalid lead byte */
        return 6;
    }
}

/*
 * Check for overlong encoding patterns
 */
static int
check_overlong(const uint8_t *data, size_t size)
{
    if (size < 2)
        return 0;
    
    /* Overlong 2-byte: C0/C1 leads */
    if (data[0] == 0xC0 || data[0] == 0xC1) {
        coverage_hint(10);
        return 1;
    }
    
    /* Overlong 3-byte: E0 with 80-9F */
    if (size >= 2 && data[0] == 0xE0 && (data[1] & 0xE0) == 0x80) {
        coverage_hint(11);
        return 1;
    }
    
    /* Overlong 4-byte: F0 with 80-8F */
    if (size >= 2 && data[0] == 0xF0 && (data[1] & 0xF0) == 0x80) {
        coverage_hint(12);
        return 1;
    }
    
    return 0;
}

/*
 * Check for surrogate pairs (invalid in UTF-8)
 */
static int
check_surrogate(const uint8_t *data, size_t size)
{
    if (size < 3)
        return 0;
    
    /* Surrogate: ED with A0-BF */
    if (data[0] == 0xED && (data[1] & 0xE0) == 0xA0) {
        coverage_hint(13);
        return 1;
    }
    
    return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct utf8_data    ud;
    char               *str;
    wchar_t             wc;
    size_t              i;
    int                 width;
    enum utf8_state     state;
    u_int               combined;

    if (size == 0 || size > FUZZER_MAXLEN)
        return 0;

    /* Classify leading bytes for coverage */
    for (i = 0; i < size && i < 8; i++) {
        classify_utf8_byte(data[i]);
    }
    
    /* Check for special patterns */
    check_overlong(data, size);
    check_surrogate(data, size);

    /* Create null-terminated string */
    str = malloc(size + 1);
    if (str == NULL)
        return 0;
    memcpy(str, data, size);
    str[size] = '\0';

    /* Test 1: utf8_isvalid - validate entire string */
    if (utf8_isvalid(str)) {
        coverage_hint(20);  /* Valid UTF-8 */
    } else {
        coverage_hint(21);  /* Invalid UTF-8 */
    }

    /* Test 2: utf8_strvis - visualize string */
    {
        char *vis_buf = malloc(size * 4 + 1);
        if (vis_buf != NULL) {
            utf8_strvis(vis_buf, str, size, VIS_OCTAL);
            coverage_hint(22);
            free(vis_buf);
        }
    }

    /* Test 3: Byte-by-byte processing */
    utf8_set(&ud, 0);
    for (i = 0; i < size && i < 64; i++) {
        state = utf8_open(&ud, data[i]);
        switch (state) {
        case UTF8_MORE:
            coverage_hint(30);
            while (++i < size && i < 64) {
                state = utf8_append(&ud, data[i]);
                if (state != UTF8_MORE)
                    break;
            }
            if (state == UTF8_DONE) {
                coverage_hint(31);  /* Complete sequence */
            }
            break;
        case UTF8_DONE:
            coverage_hint(32);  /* Single-byte char */
            break;
        default:
            coverage_hint(33);  /* Rejected */
            break;
        }
    }

    /* Test 4: utf8_towc - convert to wide char */
    utf8_set(&ud, 0);
    if (size >= 4) {
        memcpy(ud.data, data, 4);
        ud.size = 4;
        if (utf8_towc(&ud, &wc) == UTF8_DONE) {
            coverage_hint(40);
            /* Test cwidth (since utf8_width doesn't exist) */
            width = wcwidth(wc);
            if (width == 0) coverage_hint(41);
            else if (width == 1) coverage_hint(42);
            else if (width == 2) coverage_hint(43);
            else coverage_hint(44);  /* Invalid width */
        }
    }

    /* Test 5: utf8_from_data / utf8_to_data roundtrip */
    if (size >= 4) {
        struct utf8_data ud2;
        u_int            value;
        
        utf8_from_data(&ud, &combined);
        coverage_hint(50);
        
        value = combined;
        utf8_to_data(value, &ud2);
        coverage_hint(51);
    }

    /* Test 6: utf8_cstrhas - check for character presence */
    for (i = 0; i < size && i < 4; i++) {
        ud.data[i] = data[i];
    }
    ud.size = (i < 4) ? i : 4;
    
    if (utf8_cstrhas(str, &ud)) {
        coverage_hint(60);
    }

    /* Test 7: utf8_build_one for single-byte characters */
    for (i = 0; i < size && i < 8; i++) {
        utf8_build_one(data[i]);
        coverage_hint(61);
    }

    /* Test 8: Test utf8_set with different values */
    utf8_set(&ud, 0);
    for (i = 0; i < size && i < 4; i++) {
        utf8_set(&ud, data[i]);
    }
    coverage_hint(62);

    /* Test 9: utf8_strvis with different flags */
    {
        char *vis_buf2 = malloc(size * 4 + 1);
        if (vis_buf2 != NULL) {
            /* Test with VIS_CSTYLE */
            utf8_strvis(vis_buf2, str, size * 4, VIS_CSTYLE);
            coverage_hint(63);
            
            /* Test with VIS_TAB | VIS_NL */
            utf8_strvis(vis_buf2, str, size * 4, VIS_TAB | VIS_NL);
            coverage_hint(64);
            
            /* Test with combined flags */
            utf8_strvis(vis_buf2, str, size * 4, VIS_OCTAL | VIS_CSTYLE | VIS_NL);
            coverage_hint(65);
            
            free(vis_buf2);
        }
    }

    /* Test 10: Process multiple complete UTF-8 sequences */
    {
        size_t processed = 0;
        int seq_count = 0;
        
        while (processed < size && seq_count < 16) {
            state = utf8_open(&ud, data[processed]);
            processed++;
            
            if (state == UTF8_MORE) {
                while (processed < size && state == UTF8_MORE) {
                    state = utf8_append(&ud, data[processed]);
                    processed++;
                }
                if (state == UTF8_DONE) {
                    /* Convert to wchar and back */
                    if (utf8_towc(&ud, &wc) == UTF8_DONE) {
                        /* Check width of resulting character */
                        int w = wcwidth(wc);
                        if (w == 2) {
                            coverage_hint(70);  /* Wide char (CJK, etc) */
                        } else if (wc > 0x10000) {
                            coverage_hint(71);  /* Supplementary plane */
                        }
                    }
                }
            }
            seq_count++;
        }
        coverage_hint(72);
    }

    /* Test 11: Boundary testing - BOM and special characters */
    if (size >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF) {
        coverage_hint(73);  /* UTF-8 BOM */
    }
    
    /* Test 12: Zero-width characters */
    if (size >= 3 && data[0] == 0xE2 && data[1] == 0x80) {
        /* Zero-width space range: U+200B-U+200D */
        if (data[2] >= 0x8B && data[2] <= 0x8D) {
            coverage_hint(74);
        }
    }

    /* Test 13: Combining characters */
    if (size >= 3 && data[0] == 0xCC) {
        coverage_hint(75);  /* Combining diacritical marks */
    }

    free(str);
    return 0;
}

int
LLVMFuzzerInitialize(__unused int *argc, __unused char ***argv)
{
    const struct options_table_entry *oe;

    /* Initialize global state required by utf8_update_width_cache() */
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

    /* Now safe to call - global_options is initialized */
    utf8_update_width_cache();
    return 0;
}
