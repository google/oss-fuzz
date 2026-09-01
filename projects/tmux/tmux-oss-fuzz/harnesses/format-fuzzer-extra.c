/*
 * format-fuzzer-extra.c - additional harness for tmux format-string
 * expansion.
 *
 * Targets format.c (format_expand, format_expand_time, format_true,
 * format_find, format_replace, format_build_modifiers, ...).
 *
 * Exercises strings such as:
 *   "#{window_name}"             - simple variable expansion
 *   "#{?pane_active,yes,no}"     - conditional
 *   "#{==:left,right}"           - comparison
 *   "#{s/find/replace/:text}"    - substitution
 *   "#{l:UPPER}", "#{b:/p/file}" - modifier chains
 *
 * Format strings are used extensively in tmux for status bars, hooks
 * and display. Complex nested expressions are an interesting target.
 */

#include <assert.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "tmux.h"

#define FUZZER_MAXLEN    2048
#define PANE_WIDTH         80
#define PANE_HEIGHT        25

struct event_base *libevent;

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct format_tree *ft;
    struct window      *w;
    struct window_pane *wp;
    char               *fmt;
    char               *expanded;

    if (size == 0 || size > FUZZER_MAXLEN)
        return 0;

    /* Create null-terminated format string */
    fmt = malloc(size + 1);
    if (fmt == NULL)
        return 0;
    memcpy(fmt, data, size);
    fmt[size] = '\0';

    /* Create window and pane for format context */
    w = window_create(PANE_WIDTH, PANE_HEIGHT, 0, 0);
    if (w == NULL) {
        free(fmt);
        return 0;
    }
    window_add_ref(w, __func__);

    wp = window_add_pane(w, NULL, 0, 0);
    if (wp == NULL) {
        window_remove_ref(w, __func__);
        free(fmt);
        return 0;
    }

    /* Create format tree with pane/window context for callbacks */
    ft = format_create(NULL, NULL, FORMAT_NONE, 0);
    if (ft == NULL) {
        window_remove_ref(w, __func__);
        free(fmt);
        return 0;
    }

    /*
     * Register window and pane with the format tree so that format_table
     * callbacks (pane_id, pane_width, pane_height, cursor_x, cursor_y,
     * history_size, etc.) can resolve.
     */
    format_defaults_pane(ft, wp);

    /*
     * Add extra variables that are not in the format_table but are
     * commonly referenced in tmux format strings. These get found
     * via the format entry tree (ft->tree).
     */
    format_add(ft, "session_name", "%s", "fuzz-session");
    format_add(ft, "window_index", "%d", 0);
    format_add(ft, "window_name", "%s", "fuzz-window");
    format_add(ft, "window_flags", "%s", "*");
    format_add(ft, "pane_title", "%s", "fuzz-pane");
    format_add(ft, "status-left", "%s", "[#S]");
    format_add(ft, "status-right", "%s", "%H:%M %d-%b");
    format_add(ft, "test_empty", "%s", "");
    format_add(ft, "test_number", "%d", 42);
    format_add(ft, "test_zero", "%d", 0);
    format_add(ft, "test_path", "%s", "/usr/local/bin/tmux");
    format_add(ft, "test_long", "%s",
        "a]b}c,d:e#f#{g}h#{i,j}k");

    /* Test 1: format_expand - the main target */
    expanded = format_expand(ft, fmt);
    free(expanded);

    /* Test 2: format_expand_time */
    expanded = format_expand_time(ft, fmt);
    free(expanded);

    /* Test 3: format_true on the raw string */
    format_true(fmt);

    format_free(ft);

    /*
     * Test 4: Second pass with FORMAT_STATUS flag which changes some
     * behavior in format expansion.
     */
    ft = format_create(NULL, NULL, FORMAT_STATUS, 0);
    if (ft != NULL) {
        format_defaults_pane(ft, wp);
        format_add(ft, "session_name", "%s", "status-test");
        format_add(ft, "window_name", "%s", "status-win");

        expanded = format_expand(ft, fmt);
        free(expanded);

        format_free(ft);
    }

    /*
     * Test 5: Third pass with FORMAT_FORCE flag.
     */
    ft = format_create(NULL, NULL, FORMAT_FORCE, 0);
    if (ft != NULL) {
        format_defaults_window(ft, w);
        format_add(ft, "session_name", "%s", "force-test");

        expanded = format_expand(ft, fmt);
        free(expanded);

        format_free(ft);
    }

    /* Cleanup */
    window_remove_ref(w, __func__);
    free(fmt);

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
