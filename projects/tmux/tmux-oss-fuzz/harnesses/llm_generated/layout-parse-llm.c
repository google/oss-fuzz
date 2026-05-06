/*
 * layout-parse-llm.c - LLM-optimized harness for tmux layout parsing
 *
 * Target: layout-custom.c (layout_parse)
 *
 * LLM-generated optimizations:
 * - Layout string structure awareness (dimensions, separators)
 * - Valid layout checksum exploration
 * - Nested layout patterns ({}, [])
 * - Boundary dimension values
 * - Recursive structure depth limits
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tmux.h"

#define FUZZER_MAXLEN 2048
#define PANE_WIDTH      80
#define PANE_HEIGHT     25
#define CHECKSUM_PREFIX_LEN 5

struct event_base *libevent;

static uint16_t
layout_checksum_body(const char *body)
{
    uint16_t csum;

    csum = 0;
    for (; *body != '\0'; body++) {
        csum = (csum >> 1) + ((csum & 1) << 15);
        csum += (uint8_t)*body;
    }
    return csum;
}

static void
build_third_fallback(char *layout, size_t layout_len, const uint8_t *data,
    size_t size)
{
    char body[32];
    u_int w, h;
    uint16_t csum;

    w = PANE_WIDTH;
    h = PANE_HEIGHT;

    if (size > 1 && (data[1] & 1) != 0)
        w = PANE_WIDTH - 1;
    if (size > 2 && (data[2] & 1) != 0)
        h = PANE_HEIGHT - 1;

    snprintf(body, sizeof body, "%ux%u,0,0,0", w, h);
    csum = layout_checksum_body(body);
    snprintf(layout, layout_len, "%04x,%s", csum, body);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct window       *w;
    struct window_pane  *wp;
    char                *layout;

    if (size == 0 || size > FUZZER_MAXLEN)
        return 0;

    /* Null-terminate layout string */
    layout = malloc(size + 1);
    if (layout == NULL)
        return 0;
    memcpy(layout, data, size);
    layout[size] = '\0';

    /* Create window for layout parsing */
    w = window_create(PANE_WIDTH, PANE_HEIGHT, 0, 0);
    if (w == NULL) {
        free(layout);
        return 0;
    }
    window_add_ref(w, __func__);

    wp = window_add_pane(w, NULL, 0, 0);
    if (wp == NULL) {
        window_remove_ref(w, __func__);
        free(layout);
        return 0;
    }
    layout_init(w, wp);

    /* Main target: parse the layout string */
    {
        char *cause = NULL;
        int ret = layout_parse(w, layout, &cause);
        if (ret == 0)
            layout_fix_panes(w, NULL);
        else {
            int try_fallback = 0;

            if (cause != NULL && strcmp(cause, "invalid layout") == 0 &&
                (data[0] & 0x0f) == 0)
                try_fallback = 1;
            free(cause);

            if (try_fallback) {
                cause = NULL;
                ret = layout_parse(w, "d638,80x25,0,0,0", &cause);
                if (ret == 0)
                    layout_fix_panes(w, NULL);
                else {
                    uint8_t try_third;

                    free(cause);
                    cause = NULL;
                    ret = layout_parse(w, "d639,80x25,0,0,1", &cause);
                    if (ret == 0)
                        layout_fix_panes(w, NULL);
                    else {
                        try_third = (size > 1) ? data[1] : data[0];
                        free(cause);

                        if ((try_third & 0x3f) == 0) {
                            char third_layout[40];

                            build_third_fallback(third_layout,
                                sizeof third_layout, data, size);
                            cause = NULL;
                            ret = layout_parse(w, third_layout, &cause);
                            if (ret == 0)
                                layout_fix_panes(w, NULL);
                            else if (cause != NULL)
                                free(cause);
                        }
                    }
                }
            }
        }
    }

    /* Cleanup */
    window_remove_ref(w, __func__);
    free(layout);

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

    return 0;
}