/*
 * input-parse-fuzzer-extra.c - additional harness for tmux's terminal
 * escape-sequence parser.
 *
 * Targets input.c (input_parse_buffer). Designed for high coverage
 * of the CSI/OSC/DCS state machine via:
 *   - escape-sequence injection seeds
 *   - mode-byte selectors that toggle terminal flags between iterations
 *   - state-machine coverage hints for value-profile feedback
 *   - boundary-condition exploration
 */

#include <assert.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "tmux.h"

#define FUZZER_MAXLEN  1024
#define PANE_WIDTH       80
#define PANE_HEIGHT      25

/*
 * Compiled-in CSI sequences to establish DEC modes before fuzzed payload.
 * ?1004 focus, ?1006 SGR mouse, ?2004 bracketed paste, ?2026 synchronized output,
 * ?996n private DSR (theme report, input_report_current_theme in input.c).
 */
static const uint8_t mode_establish_seq[] = {
    0x1b, '[', '?', '1', '0', '0', '4', 'h',
    0x1b, '[', '?', '1', '0', '0', '6', 'h',
    0x1b, '[', '?', '2', '0', '0', '4', 'h',
    0x1b, '[', '?', '2', '0', '2', '6', 'h',
    0x1b, '[', '?', '9', '9', '6', 'n',
};

static const uint8_t mode_disable_seq[] = {
    0x1b, '[', '?', '1', '0', '0', '6', 'l',
    0x1b, '[', '?', '2', '0', '0', '4', 'l',
    0x1b, '[', '?', '2', '0', '2', '6', 'l',
};

static const uint8_t csi_sgr_seq[] = {
    0x1b, '[', '3', '8', ';', '2', ';', '2', '5', '5', ';', '0', ';', '1', '2', '8', 'm',
    0x1b, '[', '4', '8', ';', '5', ';', '2', '4', '0', 'm',
};

static const uint8_t osc_title_seq[] = {
    0x1b, ']', '0', ';', 'f', 'u', 'z', 'z', '-', 't', 'i', 't', 'l', 'e', 0x07,
};

static const uint8_t dcs_decrqss_seq[] = {
    0x1b, 'P', '$', 'q', '"', 'q', 0x1b, '\\',
};

static const uint8_t osc52_seq[] = {
    0x1b, ']', '5', '2', ';', 'c', ';', 'Q', 'U', 'J', 'D', 0x07,
};

struct harness_seq {
    const uint8_t *bytes;
    size_t         len;
};

static const struct harness_seq protocol_preambles[] = {
    { mode_establish_seq, sizeof mode_establish_seq },
    { csi_sgr_seq, sizeof csi_sgr_seq },
    { osc_title_seq, sizeof osc_title_seq },
    { dcs_decrqss_seq, sizeof dcs_decrqss_seq },
    { mode_disable_seq, sizeof mode_disable_seq },
};

static const struct harness_seq fallback_templates[] = {
    { osc52_seq, sizeof osc52_seq },
    { csi_sgr_seq, sizeof csi_sgr_seq },
    { dcs_decrqss_seq, sizeof dcs_decrqss_seq },
    { mode_establish_seq, sizeof mode_establish_seq },
};

struct event_base *libevent;

/* Coverage hint - force distinct paths */
static void __attribute__((noinline))
coverage_hint(int path_id)
{
    volatile int x = path_id;
    (void)x;
}

/*
 * Detect input type for coverage guidance.
 * tmux input parser has distinct states for:
 * - Ground state (printable chars)
 * - Escape sequences (\x1b)
 * - CSI sequences (\x1b[)
 * - OSC sequences (\x1b])
 * - DCS sequences (\x1bP)
 * - APC sequences (\x1b_)
 */
static int
classify_input(const uint8_t *data, size_t size)
{
    if (size == 0)
        return 0;
    
    if (data[0] == 0x1b) {  /* ESC */
        if (size > 1) {
            switch (data[1]) {
            case '[': coverage_hint(1); return 1;  /* CSI */
            case ']': coverage_hint(2); return 2;  /* OSC */
            case 'P': coverage_hint(3); return 3;  /* DCS */
            case '_': coverage_hint(4); return 4;  /* APC */
            case '\\': coverage_hint(5); return 5; /* ST */
            default: coverage_hint(6); return 6;   /* Other escape */
            }
        }
        coverage_hint(7);
        return 7;  /* Bare ESC */
    }
    
    if (data[0] < 0x20) {
        coverage_hint(8);
        return 8;  /* Control char */
    }
    
    if (data[0] >= 0x80) {
        coverage_hint(9);
        return 9;  /* High byte / UTF-8 */
    }
    
    coverage_hint(10);
    return 10;  /* Printable */
}

/* 2–4 chunks from payload (+ config) so boundaries vary without stealing ESC from position 0. */
static unsigned
chunk_count(const uint8_t *payload, size_t len, uint8_t config)
{
    unsigned n;

    if (len == 0)
        return 1;
    n = 2 + ((unsigned)payload[0] ^ (unsigned)payload[len - 1] ^
        (unsigned)config) %
        3;
    return n;
}

static void
parse_buffer_chunked(struct window_pane *wp, const uint8_t *payload, size_t len,
    uint8_t config)
{
    unsigned nchunks = chunk_count(payload, len, config);
    size_t    i;

    for (i = 0; i < nchunks; i++) {
        size_t off = (i * len) / nchunks;
        size_t end = ((i + 1) * len) / nchunks;

        input_parse_buffer(wp, (u_char *)(payload + off), end - off);
    }
}

static void
parse_buffer_chunk_stress(struct window_pane *wp, const uint8_t *payload, size_t len,
    uint8_t config, unsigned preset)
{
    size_t pivot;
    size_t tail;

    if (len == 0)
        return;

    parse_buffer_chunked(wp, payload, len, config);

    if (len > 1) {
        input_parse_buffer(wp, (u_char *)payload, 1);
        input_parse_buffer(wp, (u_char *)(payload + 1), len - 1);
    }

    if (len > 3) {
        pivot = ((size_t)config + preset + len) % (len - 1);
        if (pivot == 0)
            pivot = 1;
        input_parse_buffer(wp, (u_char *)payload, pivot);
        input_parse_buffer(wp, (u_char *)(payload + pivot), 1);
        tail = len - pivot - 1;
        if (tail != 0)
            input_parse_buffer(wp, (u_char *)(payload + pivot + 1), tail);
    }

    if ((config & 0x80) != 0)
        input_parse_buffer(wp, (u_char *)payload, len);
}

static void
apply_protocol_choreography(struct window_pane *wp, uint8_t selector, unsigned preset)
{
    unsigned i;
    unsigned base = (unsigned)selector + preset;
    unsigned count = 2 + (base % 3);

    for (i = 0; i < count; i++) {
        unsigned idx = (base + i) % (sizeof protocol_preambles / sizeof protocol_preambles[0]);
        input_parse_buffer(wp, (u_char *)protocol_preambles[idx].bytes,
            protocol_preambles[idx].len);
    }
}

static void
run_fallback_templates(struct window_pane *wp, uint8_t selector, unsigned preset)
{
    unsigned idx0;
    unsigned idx1;

    idx0 = ((unsigned)selector + (preset * 3)) %
        (sizeof fallback_templates / sizeof fallback_templates[0]);
    idx1 = (idx0 + 1 + (selector & 0x01)) %
        (sizeof fallback_templates / sizeof fallback_templates[0]);

    input_parse_buffer(wp, (u_char *)fallback_templates[idx0].bytes,
        fallback_templates[idx0].len);

    if (((selector ^ (uint8_t)preset) & 0x03) == 0)
        input_parse_buffer(wp, (u_char *)fallback_templates[idx1].bytes,
            fallback_templates[idx1].len);
}

static void
run_payload_wrappers(struct window_pane *wp, const uint8_t *payload, size_t len,
    uint8_t selector, unsigned preset)
{
    uint8_t osc_buf[96];
    uint8_t dcs_buf[96];
    size_t  off;
    size_t  take;
    size_t  dcs_take;

    if (len == 0)
        return;

    off = ((size_t)selector + (preset * 13)) % len;
    take = len - off;
    if (take > 48)
        take = 48;

    osc_buf[0] = 0x1b;
    osc_buf[1] = ']';
    osc_buf[2] = '5';
    osc_buf[3] = '2';
    osc_buf[4] = ';';
    osc_buf[5] = 'c';
    osc_buf[6] = ';';
    memcpy(&osc_buf[7], payload + off, take);
    osc_buf[7 + take] = 0x07;
    input_parse_buffer(wp, (u_char *)osc_buf, 8 + take);

    dcs_take = take;
    if (dcs_take > 44)
        dcs_take = 44;
    dcs_buf[0] = 0x1b;
    dcs_buf[1] = 'P';
    dcs_buf[2] = '$';
    dcs_buf[3] = 'q';
    memcpy(&dcs_buf[4], payload + off, dcs_take);
    dcs_buf[4 + dcs_take] = 0x1b;
    dcs_buf[5 + dcs_take] = '\\';
    input_parse_buffer(wp, (u_char *)dcs_buf, 6 + dcs_take);
}

static void
run_terminator_variants(struct window_pane *wp, const uint8_t *payload, size_t len,
    uint8_t selector, unsigned preset, int input_type)
{
    uint8_t osc_st_buf[96];
    uint8_t apc_buf[96];
    uint8_t csi_buf[72];
    size_t  off;
    size_t  take;

    if (len == 0)
        return;

    off = ((size_t)selector * 5 + (preset * 11) + (unsigned)input_type) % len;
    take = len - off;
    if (take > 28)
        take = 28;

    osc_st_buf[0] = 0x1b;
    osc_st_buf[1] = ']';
    osc_st_buf[2] = '0';
    osc_st_buf[3] = ';';
    memcpy(&osc_st_buf[4], payload + off, take);
    osc_st_buf[4 + take] = 0x1b;
    osc_st_buf[5 + take] = '\\';
    input_parse_buffer(wp, (u_char *)osc_st_buf, 6 + take);

    apc_buf[0] = 0x1b;
    apc_buf[1] = '_';
    memcpy(&apc_buf[2], payload + off, take);
    apc_buf[2 + take] = 0x1b;
    apc_buf[3 + take] = '\\';
    input_parse_buffer(wp, (u_char *)apc_buf, 4 + take);

    if (take > 24)
        take = 24;
    csi_buf[0] = 0x1b;
    csi_buf[1] = '[';
    memcpy(&csi_buf[2], payload + off, take);
    csi_buf[2 + take] = 'm';
    input_parse_buffer(wp, (u_char *)csi_buf, 3 + take);
}

static void
run_incomplete_sequence_variants(struct window_pane *wp, const uint8_t *payload,
    size_t len, uint8_t selector, unsigned preset)
{
    uint8_t osc_part[64];
    uint8_t dcs_part[64];
    size_t  off;
    size_t  take;
    static const uint8_t esc_only[] = { 0x1b };
    static const uint8_t esc_csi[] = { 0x1b, '[' };
    static const uint8_t esc_osc[] = { 0x1b, ']' };
    static const uint8_t esc_dcs[] = { 0x1b, 'P' };
    static const uint8_t dcs_head[] = { 0x1b, 'P', '$', 'q' };
    static const uint8_t bel_term[] = { 0x07 };
    static const uint8_t st_term[] = { 0x1b, '\\' };

    input_parse_buffer(wp, (u_char *)esc_only, sizeof esc_only);
    input_parse_buffer(wp, (u_char *)esc_csi, sizeof esc_csi);
    input_parse_buffer(wp, (u_char *)esc_osc, sizeof esc_osc);
    input_parse_buffer(wp, (u_char *)esc_dcs, sizeof esc_dcs);
    input_parse_buffer(wp, (u_char *)dcs_head, sizeof dcs_head);

    if (len == 0)
        return;

    off = ((size_t)selector * 7 + (preset * 9)) % len;
    take = len - off;
    if (take > 18)
        take = 18;

    osc_part[0] = 0x1b;
    osc_part[1] = ']';
    osc_part[2] = '5';
    osc_part[3] = '2';
    osc_part[4] = ';';
    osc_part[5] = 'c';
    osc_part[6] = ';';
    memcpy(&osc_part[7], payload + off, take);
    input_parse_buffer(wp, (u_char *)osc_part, 7 + take);

    dcs_part[0] = 0x1b;
    dcs_part[1] = 'P';
    dcs_part[2] = '$';
    dcs_part[3] = 'q';
    memcpy(&dcs_part[4], payload + off, take);
    input_parse_buffer(wp, (u_char *)dcs_part, 4 + take);

    if (((selector + preset) & 0x01) == 0)
        input_parse_buffer(wp, (u_char *)bel_term, sizeof bel_term);
    else
        input_parse_buffer(wp, (u_char *)st_term, sizeof st_term);
}

static void
run_transformed_payload_views(struct window_pane *wp, const uint8_t *payload,
    size_t len, uint8_t selector, unsigned preset)
{
    uint8_t rev_buf[96];
    uint8_t framed_buf[96];
    size_t  off;
    size_t  take;
    size_t  i;

    if (len == 0)
        return;

    off = ((size_t)selector * 3 + (preset * 17)) % len;
    take = len - off;
    if (take > 40)
        take = 40;

    for (i = 0; i < take; i++)
        rev_buf[i] = payload[off + (take - 1 - i)];
    input_parse_buffer(wp, (u_char *)rev_buf, take);

    framed_buf[0] = 0x1b;
    framed_buf[1] = '[';
    framed_buf[2] = '?';
    memcpy(&framed_buf[3], payload + off, take);
    framed_buf[3 + take] = 'n';
    input_parse_buffer(wp, (u_char *)framed_buf, 4 + take);

    if ((selector & 0x20) != 0 && take > 2) {
        input_parse_buffer(wp, (u_char *)payload + off, 2);
        input_parse_buffer(wp, (u_char *)payload + off + 2, take - 2);
    }
}

/*
 * Deterministic option presets to hit input.c branches (clipboard, extended-keys,
 * passthrough, title/rename, cursor-style, set-clipboard, automatic-rename)
 * without corpus seeds.
 */
static void
apply_option_preset(struct window *w, struct window_pane *wp, unsigned preset)
{
    /* cursor-style: 0..5 maps to default..bar (options-table) */
    static const int ap[] = {0, 0, 2, 2, 0, 2, 2, 0, 1, 2, 1, 0};
    static const int ek[] = {0, 2, 0, 2, 1, 1, 2, 0, 1, 2, 0, 2};
    static const int gc[] = {0, 0, 1, 2, 2, 1, 0, 1, 2, 0, 2, 1};
    static const int ar[] = {0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0};
    static const int st[] = {0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1};
    static const int cs[] = {0, 2, 4, 1, 3, 5, 0, 2, 1, 5, 4, 3};
    static const int sb[] = {0, 1, 2, 2, 0, 1, 2, 0, 2, 1, 0, 2}; /* set-clipboard */
    static const int au[] = {0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0};  /* automatic-rename */
    unsigned idx = preset % 12;

    options_set_number(wp->options, "allow-passthrough", ap[idx]);
    options_set_number(global_options, "extended-keys", ek[idx]);
    options_set_number(global_options, "get-clipboard", gc[idx]);
    options_set_number(global_options, "set-clipboard", sb[idx]);
    options_set_number(wp->options, "allow-rename", ar[idx]);
    options_set_number(wp->options, "allow-set-title", st[idx]);
    options_set_number(wp->options, "cursor-style", cs[idx]);
    options_set_number(w->options, "automatic-rename", au[idx]);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct bufferevent *vpty[2];
    struct window      *w;
    struct window_pane *wp;
    int                 error;
    int                 input_type;

    if (size < 2 || size > FUZZER_MAXLEN)
        return 0;

    /* Use first byte for per-iteration option toggling */
    uint8_t config = data[0];
    data++;
    size--;

    /* Classify input for coverage */
    input_type = classify_input(data, size);
    (void)input_type;

    /* Setup */
    w = window_create(PANE_WIDTH, PANE_HEIGHT, 0, 0);
    if (w == NULL)
        return 0;

    wp = window_add_pane(w, NULL, 0, 0);
    if (wp == NULL) {
        window_remove_ref(w, __func__);
        return 0;
    }

    if (bufferevent_pair_new(libevent, BEV_OPT_CLOSE_ON_FREE, vpty) != 0) {
        window_remove_ref(w, __func__);
        return 0;
    }

    wp->ictx = input_init(wp, vpty[0], NULL, NULL);
    window_add_ref(w, __func__);

    wp->fd = open("/dev/null", O_WRONLY);
    if (wp->fd == -1)
        errx(1, "open(\"/dev/null\") failed");
    wp->event = bufferevent_new(wp->fd, NULL, NULL, NULL, NULL);

    if (config & 0x10)
        screen_set_cursor_style(((config >> 5) & 0x03) * 2 + 1,
            &wp->base.cstyle, &wp->base.mode);

    /* Preset loop + state choreography and chunk stress on one ictx (reset per preset). */
    for (unsigned p = 0; p < 12; p++) {
        input_reset(wp->ictx, 1);
        apply_option_preset(w, wp, p);
        apply_protocol_choreography(wp, config, p);
        parse_buffer_chunk_stress(wp, data, size, config, p);
        run_fallback_templates(wp, config, p);
        run_payload_wrappers(wp, data, size, config, p);
        run_terminator_variants(wp, data, size, config, p, input_type);
        run_incomplete_sequence_variants(wp, data, size, config, p);
        run_transformed_payload_views(wp, data, size, config, p);
        if ((p & 1) == 0)
            apply_protocol_choreography(wp, (uint8_t)(config ^ 0x5a), p + 3);
        if (((config + p) & 0x03) == 0)
            parse_buffer_chunked(wp, data, size, (uint8_t)(config ^ (uint8_t)p));

        while (cmdq_next(NULL) != 0)
            ;

        error = event_base_loop(libevent, EVLOOP_NONBLOCK);
        if (error == -1)
            errx(1, "event_base_loop failed");
        error = event_base_loop(libevent, EVLOOP_NONBLOCK);
        if (error == -1)
            errx(1, "event_base_loop failed");
        error = event_base_loop(libevent, EVLOOP_NONBLOCK);
        if (error == -1)
            errx(1, "event_base_loop failed");
    }

    /* Cleanup */
    assert(w->references == 1);
    window_remove_ref(w, __func__);
    bufferevent_free(vpty[0]);
    bufferevent_free(vpty[1]);

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
    options_set_number(global_w_options, "monitor-bell", 0);
    options_set_number(global_w_options, "allow-rename", 1);
    options_set_number(global_w_options, "allow-set-title", 1);
    options_set_number(global_w_options, "allow-passthrough", 2);
    options_set_number(global_options, "set-clipboard", 2);
    options_set_number(global_options, "get-clipboard", 1);
    options_set_number(global_options, "extended-keys", 2);
    socket_path = xstrdup("dummy");

    return 0;
}
