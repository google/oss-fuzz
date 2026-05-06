/*
 * format-llm.c - LLM-optimized harness for tmux format string expansion
 *
 * Target: format.c (format_expand, format_expand_time, format_create)
 *
 * LLM-generated optimizations:
 * - Format placeholder awareness (#{...}, #(...), #[...])
 * - Conditional expression coverage (?, ==, !=, <, >)
 * - Variable substitution patterns
 * - Nested format exploration
 * - Time format specifiers
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "tmux.h"

#define FUZZER_MAXLEN 4096

struct event_base *libevent;

/* Coverage hint - force distinct paths */
static void __attribute__((noinline))
coverage_hint(int path_id)
{
    volatile int x = path_id;
    (void)x;
}

/* Common format variables for dictionary-aware fuzzing */
static const char *format_vars[] = {
    "pane_id", "pane_index", "pane_width", "pane_height",
    "window_id", "window_index", "window_name", "window_width",
    "session_name", "session_id", "session_created",
    "host", "host_short", "pid",
    "cursor_x", "cursor_y", "scroll_position",
    "alternate_on", "mouse", "selection_present",
    "pane_current_command", "pane_current_path", "pane_tty",
    "client_name", "client_tty", "client_activity",
    "buffer_name", "buffer_size", "buffer_sample",
    NULL
};

/* Time format specifiers for coverage */
static const char *time_specs[] = {
    "%Y", "%m", "%d", "%H", "%M", "%S", "%Z", "%z",
    "%c", "%x", "%X", "%r", "%R", "%T", "%F", "%D",
    NULL
};

/*
 * Analyze format string structure
 */
static void
analyze_format(const char *str, size_t len)
{
    size_t i;
    int has_hash = 0, has_brace = 0, has_paren = 0;
    int has_cond = 0, has_compare = 0;
    int nest_depth = 0;
    
    for (i = 0; i < len && str[i] != '\0'; i++) {
        switch (str[i]) {
        case '#':
            has_hash = 1;
            if (i + 1 < len) {
                switch (str[i + 1]) {
                case '{': coverage_hint(1); break;  /* Variable */
                case '(': coverage_hint(2); break;  /* Command */
                case '[': coverage_hint(3); break;  /* Style */
                case '#': coverage_hint(4); break;  /* Literal # */
                case 'H': coverage_hint(5); break;  /* Host */
                case 'I': coverage_hint(6); break;  /* Window index */
                case 'W': coverage_hint(7); break;  /* Window name */
                }
            }
            break;
        case '{':
            nest_depth++;
            has_brace = 1;
            coverage_hint(10 + (nest_depth % 3));
            break;
        case '}':
            nest_depth--;
            break;
        case '(':
            has_paren = 1;
            coverage_hint(13);
            break;
        case '?':
            has_cond = 1;
            coverage_hint(14);
            break;
        case '=':
            if (i + 1 < len && str[i + 1] == '=') {
                has_compare = 1;
                coverage_hint(15);
            }
            break;
        case '!':
            if (i + 1 < len && str[i + 1] == '=') {
                has_compare = 1;
                coverage_hint(16);
            }
            break;
        case '<':
        case '>':
            has_compare = 1;
            coverage_hint(17);
            break;
        case ',':
            if (nest_depth > 0) {
                coverage_hint(18);  /* Conditional separator */
            }
            break;
        case ':':
            coverage_hint(19);  /* Modifier */
            break;
        case '%':
            coverage_hint(20);  /* Time format */
            break;
        }
    }
    
    if (has_hash && has_brace) coverage_hint(30);
    if (has_cond && has_compare) coverage_hint(31);
    if (has_paren) coverage_hint(32);
    (void)has_paren;
}

/*
 * Check for known format variables
 */
static void
check_known_vars(const char *str)
{
    const char **p;
    
    for (p = format_vars; *p != NULL; p++) {
        if (strstr(str, *p) != NULL) {
            coverage_hint(40 + (int)(p - format_vars) % 10);
            return;
        }
    }
    coverage_hint(50);  /* Unknown variable */
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct format_tree *ft;
    char               *format, *result;

    if (size == 0 || size > FUZZER_MAXLEN)
        return 0;

    /* Null-terminate format string */
    format = malloc(size + 1);
    if (format == NULL)
        return 0;
    memcpy(format, data, size);
    format[size] = '\0';

    /* Analyze for coverage hints */
    analyze_format(format, size);
    check_known_vars(format);

    /* Create format tree with flags */
    ft = format_create(NULL, NULL, FORMAT_NONE, 0);
    if (ft == NULL) {
        free(format);
        return 0;
    }

    /* Add some test variables to the format tree */
    format_add(ft, "test_var", "%s", "test_value");
    format_add(ft, "test_num", "%d", 42);
    format_add(ft, "empty_var", "%s", "");
    format_add(ft, "long_var", "%s", 
        "this_is_a_very_long_variable_value_for_testing_buffer_handling");

    /* Test 1: format_expand - main entry point */
    result = format_expand(ft, format);
    if (result != NULL) {
        coverage_hint(60);
        free(result);
    } else {
        coverage_hint(61);
    }

    /* Test 2: format_expand_time - time-aware expansion */
    result = format_expand_time(ft, format);
    if (result != NULL) {
        coverage_hint(62);
        free(result);
    } else {
        coverage_hint(63);
    }

    /* Test 3: Expand with different format flags */
    format_free(ft);
    
    /* Test with NOJOBS flag */
    ft = format_create(NULL, NULL, FORMAT_NOJOBS, 0);
    if (ft != NULL) {
        result = format_expand(ft, format);
        if (result != NULL) {
            coverage_hint(64);
            free(result);
        }
        format_free(ft);
    }

    /* Test with FORCE flag */
    ft = format_create(NULL, NULL, FORMAT_FORCE, 0);
    if (ft != NULL) {
        result = format_expand(ft, format);
        if (result != NULL) {
            coverage_hint(65);
            free(result);
        }
        format_free(ft);
    }

    /* Test with VERBOSE flag for debugging paths */
    ft = format_create(NULL, NULL, FORMAT_VERBOSE, 0);
    if (ft != NULL) {
        format_add(ft, "test_var", "%s", "verbose_value");
        result = format_expand(ft, format);
        if (result != NULL) {
            coverage_hint(66);
            free(result);
        }
        format_free(ft);
    }

    /* Test with STATUS flag (status line context) */
    ft = format_create(NULL, NULL, FORMAT_STATUS, 0);
    if (ft != NULL) {
        format_add(ft, "pane_active", "%d", 1);
        format_add(ft, "window_active", "%d", 0);
        result = format_expand(ft, format);
        if (result != NULL) {
            coverage_hint(67);
            free(result);
        }
        format_free(ft);
    }

    /* Test nested conditionals with real variables */
    ft = format_create(NULL, NULL, FORMAT_NONE, 0);
    if (ft != NULL) {
        format_add(ft, "pane_active", "%d", 1);
        format_add(ft, "window_zoomed_flag", "%d", 0);
        format_add(ft, "pane_index", "%d", 3);
        format_add(ft, "window_index", "%d", 0);
        format_add(ft, "pane_width", "%d", 80);
        format_add(ft, "pane_height", "%d", 24);
        
        result = format_expand(ft, format);
        if (result != NULL) {
            /* Check for conditional expansion */
            if (strstr(format, "?") != NULL && strlen(result) > 0) {
                coverage_hint(68);
            }
            free(result);
        }
        format_free(ft);
    }

    /* Test format modifiers: = (padding), : (substitution) */
    if (strstr(format, "=") != NULL || strstr(format, ":") != NULL) {
        coverage_hint(69);
        ft = format_create(NULL, NULL, FORMAT_NONE, 0);
        if (ft != NULL) {
            format_add(ft, "host", "%s", "testhost.example.com");
            format_add(ft, "pane_current_path", "%s", "/very/long/path/to/directory");
            result = format_expand(ft, format);
            if (result != NULL) {
                coverage_hint(70);
                free(result);
            }
            format_free(ft);
        }
    }

    free(format);
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
