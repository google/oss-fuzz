/*
 * cmd-parse-fuzzer.c - Manual harness for tmux command parsing
 *
 * Target: cmd-parse.y (cmd_parse_from_buffer)
 * Fuzzes the tmux command parser which handles commands like:
 *   "new-window -n foo", "bind-key C-a send-prefix", etc.
 *
 * This is a high-value target as command injection could lead to
 * arbitrary command execution.
 */

#include <assert.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/lsan_interface.h>

#include "tmux.h"

#define FUZZER_MAXLEN 4096

struct event_base *libevent;

static const char *seed_inputs[] = {
    /* simple commands */
    "new-window",
    "split-window -h",
    "select-pane -t 0",
    "send-keys C-c Enter",
    "detach-client",
    /* options */
    "set-option -g status on",
    "set-option -gw automatic-rename off",
    "set-window-option -g monitor-activity on",
    /* targets */
    "select-window -t :1",
    "select-pane -t {last}",
    "select-pane -t {next}",
    "kill-pane -t %0",
    /* quoting */
    "new-window -n 'my window'",
    "new-window -n \"my window\"",
    "run-shell 'echo hello'",
    /* chained */
    "new-window ; split-window -h",
    "select-pane -t 0 ; send-keys q Enter",
    /* braces / if-shell */
    "if-shell 'true' { new-window } { split-window }",
    "if-shell '' { split-window -h }",
    /* format strings (opaque to parser — exercises token path) */
    "display-message '#{session_name}'",
    "new-window -n '#{pane_title}'",
    /* bind-key */
    "bind-key q detach-client",
    "bind-key -n C-a new-window",
    /* multiline / continuation */
    "new-window\nsplit-window -h",
    "set-option -g status on\nbind-key r source-file ~/.tmux.conf",
    NULL
};

/* ── dictionary tokens (used by custom mutator) ──────────────────────────── */

static const char *cmd_tokens[] = {
    "new-session", "new-window", "split-window", "select-pane",
    "select-window", "rename-window", "rename-session",
    "send-keys", "send-prefix",
    "bind-key", "unbind-key",
    "set-option", "set-window-option", "set-hook",
    "set-environment", "show-environment",
    "source-file", "run-shell",
    "if-shell", "while",
    "display-message", "display-popup", "display-menu",
    "copy-mode", "paste-buffer", "choose-buffer",
    "kill-pane", "kill-window", "kill-session", "kill-server",
    "detach-client", "attach-session", "switch-client",
    "resize-pane", "resize-window",
    "list-panes", "list-windows", "list-sessions", "list-clients",
    "move-pane", "move-window", "join-pane", "break-pane",
    "pipe-pane", "respawn-pane", "respawn-window",
    "save-buffer", "load-buffer", "delete-buffer",
    "refresh-client", "clock-mode",
    "command-prompt", "confirm-before",
    "lock-client", "lock-server", "lock-session",
    "-t", "-s", "-n", "-c", "-e", "-g", "-u", "-w",
    "-h", "-v", "-b", "-d", "-f", "-p", "-l",
    "-x", "-y", "-P", "-F", "-I", "-T",
    "{last}", "{next}", "{prev}", "{top}", "{bottom}",
    "{left}", "{right}", "{up}", "{down}",
    "{start}", "{end}", "{marked}", "{mouse}",
    "#{session_name}", "#{window_name}", "#{pane_title}",
    "#{pane_id}", "#{window_index}", "#{session_id}",
    "#{?pane_active,yes,no}", "#{=20:pane_title}",
    "#[fg=red]", "#[bg=blue,bold]", "#[default]",
    "#{pane_current_command}", "#{pane_current_path}",
    " ; ", "\n", " \\; ",
    "\"\"", "''", "{}",
    "on", "off", "any", "none", "external",
    NULL
};

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct cmd_parse_input	 pi;
	struct cmd_parse_result	*pr;
    char            *copy;

    // Don't process empty input
    if (size < 1 || size > 4096) return 0;

    copy = malloc(size + 1);
    if (copy == NULL) return 0;
    memcpy(copy, data, size);
    copy[size] = '\0';

    memset(&pi, 0, sizeof pi);

    pi.file = "fuzz_input";
    pi.line = 1;
    // CMD_PARSE_QUIET prevents the parser from printing error messages to stderr,
    // which significantly speeds up the fuzzer.
    pi.flags = CMD_PARSE_QUIET;

    __lsan_disable();
    pr = cmd_parse_from_string(copy, &pi);
    __lsan_enable();

    /* Handle result and cleanup */
    if (pr != NULL) {
        if (pr->status == CMD_PARSE_SUCCESS && pr->cmdlist != NULL) {
            cmd_list_free(pr->cmdlist);
        } else if (pr->status == CMD_PARSE_ERROR) {
            free(pr->error);
        }
    }

    free(copy);
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
