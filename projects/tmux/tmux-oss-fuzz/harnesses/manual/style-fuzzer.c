/*
 * style-fuzzer.c - Manual harness for tmux style parsing
 *
 * Target: style.c (style_parse)
 * Fuzzes the style string parser which handles strings like:
 *   "fg=red,bg=blue,bold", "align=centre,list=on", "range=user|foo"
 *
 * Styles control colors and attributes throughout tmux.
 * Parsing bugs could cause memory corruption or crashes.
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

/* Known style attributes */
static const char *style_attrs[] = {
    "fg=", "bg=", "fill=",
    "bold", "dim", "underscore", "blink", "reverse", "hidden",
    "italics", "strikethrough", "double-underscore", "curly-underscore",
    "dotted-underscore", "dashed-underscore", "overline",
    "nobold", "nodim", "nounderscore", "noblink", "noreverse",
    "noitalics", "nostrikethrough", "nooverline",
    "align=", "list=", "range=", "push-default", "pop-default",
    "default", "none",
    NULL
};

/* Color names */
static const char *color_names[] = {
    "black", "red", "green", "yellow", "blue", "magenta", "cyan", "white",
    "default", "terminal", "bright", "colour",
    NULL
};

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct style      sy;
    struct grid_cell  gc;
    char             *style_str;
    const char       *result_str;
    int               ret;

    if (size == 0 || size > FUZZER_MAXLEN)
        return 0;

    /* Create null-terminated style string */
    style_str = malloc(size + 1);
    if (style_str == NULL)
        return 0;
    memcpy(style_str, data, size);
    style_str[size] = '\0';

    /* Initialize style and grid cell */
    memset(&sy, 0, sizeof(sy));
    memset(&gc, 0, sizeof(gc));
    gc.fg = 8;  /* Default foreground */
    gc.bg = 8;  /* Default background */

    /* Parse the style string - the main target */
    ret = style_parse(&sy, &gc, style_str);

    /* If parsing succeeded, test round-trip */
    if (ret == 0) {
        /* Convert style back to string */
        result_str = style_tostring(&sy);
        (void)result_str;  /* Use the result to prevent optimization */
    }

    /* Test with NULL base cell */
    // memset(&sy, 0, sizeof(sy));
    // style_parse(&sy, NULL, style_str);

    /* Test style_set */
    memset(&sy, 0, sizeof(sy));
    style_set(&sy, &gc);

    free(style_str);
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
