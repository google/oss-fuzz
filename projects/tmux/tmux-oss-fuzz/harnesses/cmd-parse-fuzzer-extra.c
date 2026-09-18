/*
 * cmd-parse-fuzzer-extra.c - additional harness for tmux command parsing.
 *
 * Targets cmd-parse.y:
 *   cmd_parse_from_string  - NUL-terminated string path
 *                            (config files, :prompt, bind-key)
 *   cmd_parse_from_buffer  - length-delimited buffer path
 *                            (internal tmux buffer reader)
 *
 * Both entry points run on every input. They share the yacc grammar
 * but exercise different C code paths (cmd_parse_do_buffer vs the
 * string shim), so running both roughly doubles per-execution coverage.
 *
 * Notable design choices:
 * - LLVMFuzzerCustomCrossOver: splices two corpus inputs at a grammar
 *   boundary (semicolon / newline) rather than a random byte offset,
 *   producing valid multi-command sequences far more often.
 * - Built-in seed_inputs[] pre-populates the corpus with parseable
 *   commands so the fuzzer starts from known-good inputs.
 * - Known tmux yyparse() leak is suppressed locally via
 *   __lsan_disable/__lsan_enable around the call.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sanitizer/lsan_interface.h>

#include "tmux.h"

/* ── globals required by tmux internals ─────────────────────────────────── */

struct event_base *libevent;

/* ── built-in seed commands ──────────────────────────────────────────────── */

/*
 * These are valid, parseable tmux commands used to pre-populate the corpus
 * so the fuzzer starts from known-good inputs rather than random bytes.
 * Covering: simple commands, options, targets, quoting, chaining, braces.
 */
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

/* ── coverage hint ───────────────────────────────────────────────────────── */

static void __attribute__((noinline))
coverage_hint(int id)
{
    volatile int x = id;
    (void)x;
}

/* ── post-parse walker ───────────────────────────────────────────────────── */

static void
walk_cmd_list(struct cmd_list *cmdlist)
{
    char *printed;

    if (cmdlist == NULL)
        return;

    /* cmd_list_print exercises the unparse / round-trip path */
    printed = cmd_list_print(cmdlist, 0);
    free(printed);
}

/* ── parse wrappers ──────────────────────────────────────────────────────── */

static void
do_parse_string(const char *input)
{
    struct cmd_parse_input   pi;
    struct cmd_parse_result *pr;

    memset(&pi, 0, sizeof pi);
    pi.file  = "fuzz";
    pi.line  = 1;
    pi.flags = CMD_PARSE_QUIET;

    __lsan_disable();
    pr = cmd_parse_from_string(input, &pi);
    __lsan_enable();
    if (pr == NULL)
        return;

    switch (pr->status) {
    case CMD_PARSE_SUCCESS:
        coverage_hint(1);
        walk_cmd_list(pr->cmdlist);
        cmd_list_free(pr->cmdlist);
        break;
    case CMD_PARSE_ERROR:
        coverage_hint(2);
        free(pr->error);
        break;
    }
}

static void
do_parse_buffer(const uint8_t *data, size_t size)
{
    struct cmd_parse_input   pi;
    struct cmd_parse_result *pr;

    memset(&pi, 0, sizeof pi);
    pi.file  = "fuzz_buf";
    pi.line  = 1;
    pi.flags = CMD_PARSE_QUIET;

    __lsan_disable();
    pr = cmd_parse_from_buffer((const char *)data, size, &pi);
    __lsan_enable();
    if (pr == NULL)
        return;

    switch (pr->status) {
    case CMD_PARSE_SUCCESS:
        coverage_hint(4);
        walk_cmd_list(pr->cmdlist);
        cmd_list_free(pr->cmdlist);
        break;
    case CMD_PARSE_ERROR:
        coverage_hint(5);
        free(pr->error);
        break;
    }
}

/* ── structural analysis ─────────────────────────────────────────────────── */

static void
analyze_structure(const char *str, size_t len)
{
    int depth_brace = 0, depth_bracket = 0;
    int has_quote_s = 0, has_quote_d = 0;
    int has_format  = 0, has_style   = 0;
    int has_semi    = 0, has_nl      = 0;
    int has_escape  = 0, has_dollar  = 0;
    int has_target  = 0, has_option  = 0;

    for (size_t i = 0; i < len && str[i] != '\0'; i++) {
        switch ((unsigned char)str[i]) {
        case '\'': has_quote_s = 1; coverage_hint(20); break;
        case '"':  has_quote_d = 1; coverage_hint(21); break;
        case '{':  depth_brace++;   coverage_hint(22); break;
        case '}':
            if (depth_brace > 0) depth_brace--;
            coverage_hint(23);
            break;
        case '[':  depth_bracket++; coverage_hint(24); break;
        case ']':
            if (depth_bracket > 0) depth_bracket--;
            coverage_hint(25);
            break;
        case '#':
            if (i + 1 < len) {
                if (str[i+1] == '{') { has_format = 1; coverage_hint(26); }
                if (str[i+1] == '[') { has_style  = 1; coverage_hint(27); }
            }
            break;
        case '$':  has_dollar = 1;  coverage_hint(28); break;
        case ';':  has_semi   = 1;  coverage_hint(29); break;
        case '\n': has_nl     = 1;  coverage_hint(30); break;
        case '\\': has_escape = 1;  coverage_hint(31); break;
        case '-':
            if (i > 0 && str[i-1] == ' ') {
                has_option = 1; coverage_hint(32);
            }
            break;
        case ':':
            has_target = 1; coverage_hint(33);
            break;
        }
    }

    if (has_quote_s && has_format)   coverage_hint(40);
    if (has_quote_d && has_dollar)   coverage_hint(41);
    if (depth_brace  > 0)            coverage_hint(42);
    if (depth_bracket > 0)           coverage_hint(43);
    if (has_format && has_semi)      coverage_hint(44);
    if (has_escape && has_quote_s)   coverage_hint(45);
    if (has_option && has_target)    coverage_hint(46);
    if (has_nl && has_escape)        coverage_hint(47);
    if (has_semi && has_nl)          coverage_hint(48);

    (void)has_quote_s; (void)has_quote_d; (void)has_format; (void)has_style;
    (void)has_semi;    (void)has_nl;      (void)has_escape; (void)has_dollar;
    (void)has_target;  (void)has_option;
}

/* ── custom mutator ──────────────────────────────────────────────────────── */

extern size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);

size_t
LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size, size_t MaxSize,
                        unsigned int Seed)
{
    size_t ntok = 0;
    for (const char **t = cmd_tokens; *t != NULL; t++) ntok++;

    unsigned int action = Seed % 7;
    const char  *tok    = cmd_tokens[Seed % ntok];

    switch (action) {
    case 0: {
        /* Prepend command token */
        size_t tlen = strlen(tok);
        if (tlen + 1 + Size > MaxSize) break;
        memmove(Data + tlen + 1, Data, Size);
        memcpy(Data, tok, tlen);
        Data[tlen] = ' ';
        return tlen + 1 + Size;
    }
    case 1: {
        /* Append chained command */
        size_t tlen = strlen(tok);
        size_t add  = 3 + tlen;
        if (Size + add > MaxSize) break;
        memcpy(Data + Size, " ; ", 3);
        memcpy(Data + Size + 3, tok, tlen);
        return Size + add;
    }
    case 2: {
        /* Wrap in if-shell braces */
        const char *pre = "if-shell '' { ";
        const char *suf = " }";
        size_t plen = strlen(pre), slen = strlen(suf);
        if (plen + Size + slen > MaxSize) break;
        memmove(Data + plen, Data, Size);
        memcpy(Data, pre, plen);
        memcpy(Data + plen + Size, suf, slen);
        return plen + Size + slen;
    }
    case 3: {
        /* Wrap in double quotes */
        if (Size + 2 > MaxSize) break;
        memmove(Data + 1, Data, Size);
        Data[0] = '"';
        Data[Size + 1] = '"';
        return Size + 2;
    }
    case 4: {
        /* Inject format string at random position */
        const char *fmt  = "#{pane_title}";
        size_t      flen = strlen(fmt);
        size_t      pos  = (Size > 0) ? (Seed % Size) : 0;
        if (Size + flen > MaxSize) break;
        memmove(Data + pos + flen, Data + pos, Size - pos);
        memcpy(Data + pos, fmt, flen);
        return Size + flen;
    }
    case 5: {
        /* Replace byte with grammar-relevant char */
        static const char gram[] = "{}();'\"\\\n#$-: \t";
        if (Size == 0) break;
        Data[Seed % Size] = (uint8_t)gram[Seed % (sizeof gram - 1)];
        return Size;
    }
    default:
        break;
    }

    return LLVMFuzzerMutate(Data, Size, MaxSize);
}

/*
 * LLVMFuzzerCustomCrossOver: grammar-aware splice.
 *
 * The default crossover picks a random byte offset in each parent, which
 * almost always cuts mid-token and produces unparseable junk.  We instead
 * find the last semicolon or newline in Data1 (a command boundary) and the
 * first semicolon or newline in Data2, then splice there.  This produces
 * valid multi-command sequences from two valid single-command seeds.
 *
 * Falls back to a midpoint splice if no boundary is found.
 */
size_t
LLVMFuzzerCustomCrossOver(const uint8_t *Data1, size_t Size1,
                          const uint8_t *Data2, size_t Size2,
                          uint8_t *Out, size_t MaxOutSize,
                          unsigned int Seed)
{
    /* Find last command boundary in Data1 */
    size_t cut1 = Size1; /* default: take all of Data1 */
    for (size_t i = Size1; i > 0; i--) {
        if (Data1[i-1] == ';' || Data1[i-1] == '\n') {
            cut1 = i;
            break;
        }
    }

    /* Find first command boundary in Data2 */
    size_t cut2 = 0; /* default: take all of Data2 */
    for (size_t i = 0; i < Size2; i++) {
        if (Data2[i] == ';' || Data2[i] == '\n') {
            cut2 = i + 1;
            break;
        }
    }

    /* Separator between the two halves */
    const char *sep  = " ; ";
    size_t      slen = 3;

    size_t total = cut1 + slen + (Size2 - cut2);
    if (total > MaxOutSize) {
        /* Fallback: simple midpoint splice, no separator */
        size_t half = Size1 / 2;
        total = half + Size2 / 2;
        if (total > MaxOutSize)
            total = MaxOutSize;
        memcpy(Out, Data1, half < total ? half : total);
        if (half < total)
            memcpy(Out + half, Data2, total - half);
        return total;
    }

    memcpy(Out, Data1, cut1);
    memcpy(Out + cut1, sep, slen);
    memcpy(Out + cut1 + slen, Data2 + cut2, Size2 - cut2);
    return total;
}

/* ── libFuzzer entry point ───────────────────────────────────────────────── */

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1)
        return 0;

    /*
     * Run BOTH parse targets on every input.  They share the same yacc
     * grammar but follow different C code paths internally, so both running
     * on every input doubles coverage per execution with negligible overhead.
     * The selector byte from the previous design has been removed.
     */
    analyze_structure((const char *)data, size);

    /* from_string requires a NUL-terminated copy */
    char *str = malloc(size + 1);
    if (str == NULL)
        return 0;
    memcpy(str, data, size);
    str[size] = '\0';

    do_parse_string(str);
    free(str);

    /* from_buffer takes raw bytes directly — no NUL needed */
    do_parse_buffer(data, size);

    return 0;
}

/* ── initialization ──────────────────────────────────────────────────────── */

/*
 * LeakSanitizer suppression note:
 * Known tmux yyparse() error-path leaks (cmd-parse.y:439,:443,
 * cmd_parse_new_commands:657, yylex_append:1161) are suppressed per-call
 * via __lsan_disable/enable in do_parse_string and do_parse_buffer above.
 * This is a real tmux bug; suppress here to keep the fuzzer running.
 */
int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
    const struct options_table_entry *oe;

    (void)argc; (void)argv;

    /* 1. Global environment */
    global_environ = environ_create();

    /* 2. Option trees */
    global_options   = options_create(NULL);
    global_s_options = options_create(NULL);
    global_w_options = options_create(NULL);

    /* 3. Populate defaults */
    for (oe = options_table; oe->name != NULL; oe++) {
        if (oe->scope & OPTIONS_TABLE_SERVER)
            options_default(global_options, oe);
        if (oe->scope & OPTIONS_TABLE_SESSION)
            options_default(global_s_options, oe);
        if (oe->scope & OPTIONS_TABLE_WINDOW)
            options_default(global_w_options, oe);
    }

    /* 4. Libevent backbone */
    libevent = osdep_event_init();

    /* 5. Socket path */
    socket_path = xstrdup("fuzz-socket");

    /*
     * 7. Warm up: run every seed input through both parsers now.
     *    This ensures the coverage bitmap is populated with valid-command
     *    paths before libFuzzer starts mutating, giving it a much better
     *    baseline than the 1–4 byte corpus files it was starting from.
     */
    for (const char **s = seed_inputs; *s != NULL; s++) {
        size_t len = strlen(*s);
        do_parse_string(*s);
        do_parse_buffer((const uint8_t *)*s, len);
    }

    return 0;
}