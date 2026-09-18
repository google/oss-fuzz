/*
 * layout-parse-fuzzer-extra.c - additional harness for tmux layout
 * parsing.
 *
 * Targets layout-custom.c (layout_parse). Layout strings encode how
 * panes are arranged in a window:
 *   "34x80,0,0{17x80,0,0,1,16x80,18,0,2}"
 *
 * Malformed layouts may cause crashes or memory corruption, which is
 * what this target is designed to surface.
 */

#include <assert.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "tmux.h"

#define FUZZER_MAXLEN 2048
#define PANE_WIDTH    80
#define PANE_HEIGHT   25

struct event_base *libevent;

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct window *w;
    char          *layout_str;
    char          *cause = NULL;
    int            ret;

    if (size == 0 || size > FUZZER_MAXLEN)
        return 0;

    /* Create null-terminated layout string */
    layout_str = malloc(size + 1);
    if (layout_str == NULL)
        return 0;
    memcpy(layout_str, data, size);
    layout_str[size] = '\0';

    /* Create a window for layout parsing */
    w = window_create(PANE_WIDTH, PANE_HEIGHT, 0, 0);
    if (w == NULL) {
        free(layout_str);
        return 0;
    }
    window_add_ref(w, __func__);

    /* Add a pane - layout_parse needs at least one pane */
    if (window_add_pane(w, NULL, 0, 0) == NULL) {
        window_remove_ref(w, __func__);
        free(layout_str);
        return 0;
    }

    /* Parse the layout string - the main target */
    ret = layout_parse(w, layout_str, &cause);

    /* Free error cause if parsing failed */
    if (ret != 0 && cause != NULL)
        free(cause);

    /* Cleanup */
    window_remove_ref(w, __func__);
    free(layout_str);

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
