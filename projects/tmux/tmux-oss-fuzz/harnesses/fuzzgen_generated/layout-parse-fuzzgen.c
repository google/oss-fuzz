/*
 * layout-parse-fuzzgen.c - FuzzGen-style harness for tmux layout parsing
 *
 * Target: layout-custom.c (layout_parse)
 *
 * FuzzGen approach:
 * - Structured layout generation
 * - Dimension control bytes
 * - Nesting depth control
 * - Checksum manipulation
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "tmux.h"

#define FUZZER_MAXLEN 2048
#define MAX_NEST_DEPTH 8

struct event_base *libevent;

/* Simple data provider */
struct data_provider {
    const uint8_t *data;
    size_t         size;
    size_t         pos;
};

static void
dp_init(struct data_provider *dp, const uint8_t *data, size_t size)
{
    dp->data = data;
    dp->size = size;
    dp->pos = 0;
}

static uint8_t
dp_consume_byte(struct data_provider *dp)
{
    if (dp->pos >= dp->size)
        return 0;
    return dp->data[dp->pos++];
}

static size_t
dp_remaining(struct data_provider *dp)
{
    return (dp->pos < dp->size) ? (dp->size - dp->pos) : 0;
}

static const uint8_t *
dp_consume_bytes(struct data_provider *dp, size_t count)
{
    const uint8_t *ptr;
    if (dp->pos + count > dp->size)
        count = dp->size - dp->pos;
    ptr = dp->data + dp->pos;
    dp->pos += count;
    return ptr;
}

/*
 * Calculate layout checksum (same as tmux)
 */
static uint16_t
calc_checksum(const char *layout)
{
    uint16_t csum = 0;
    const char *p;
    
    for (p = layout; *p != '\0'; p++)
        csum = (csum >> 1) + ((csum & 1) << 15) + (uint8_t)*p;
    return csum;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct data_provider  dp;
    struct window        *w;
    struct window_pane   *wp;
    char                 *layout;
    char                  header[32];
    uint8_t               mode;
    uint8_t               width_byte, height_byte;
    int                   width, height;
    size_t                payload_len;
    const uint8_t        *payload;

    if (size < 4)
        return 0;

    dp_init(&dp, data, size);

    /* Consume control bytes */
    mode = dp_consume_byte(&dp);
    width_byte = dp_consume_byte(&dp);
    height_byte = dp_consume_byte(&dp);
    
    /* Map to reasonable dimensions */
    width = 20 + (width_byte % 200);    /* 20-219 */
    height = 5 + (height_byte % 100);   /* 5-104 */

    payload_len = dp_remaining(&dp);
    if (payload_len == 0)
        return 0;
    if (payload_len > FUZZER_MAXLEN - 32)
        payload_len = FUZZER_MAXLEN - 32;
    
    payload = dp_consume_bytes(&dp, payload_len);

    /* Allocate layout buffer */
    layout = malloc(FUZZER_MAXLEN);
    if (layout == NULL)
        return 0;

    /* Build layout string based on mode */
    switch (mode % 3) {
    case 0:
        /* Mode 0: Use raw payload with dimensions header */
        snprintf(header, sizeof(header), "%dx%d,0,0", width, height);
        memcpy(layout, payload, payload_len);
        layout[payload_len] = '\0';
        break;
    
    case 1:
        /* Mode 1: Prepend valid-looking header with checksum */
        memcpy(layout + 16, payload, payload_len);
        layout[16 + payload_len] = '\0';
        
        /* Calculate checksum for rest of layout */
        uint16_t csum = calc_checksum(layout + 16);
        snprintf(layout, 16, "%04x,%dx%d,", csum, width, height);
        /* Fix the layout by removing null from snprintf */
        layout[strlen(layout)] = layout[16] ? layout[16] : ',';
        break;
    
    case 2:
        /* Mode 2: Generate structured layout fragment */
        snprintf(layout, FUZZER_MAXLEN, 
            "%dx%d,0,0{%.*s}", 
            width, height, 
            (int)payload_len, payload);
        break;
    }

    /* Create window */
    w = window_create(width, height, 0, 0);
    if (w == NULL) {
        free(layout);
        return 0;
    }

    wp = window_add_pane(w, NULL, 0, 0);
    if (wp == NULL) {
        window_remove_ref(w, __func__);
        free(layout);
        return 0;
    }

    /* Parse layout */
    {
        char *cause = NULL;
        int ret = layout_parse(w, layout, &cause);
        if (ret == 0) {
            /* Exercise operations on successful parse */
            layout_fix_panes(w, NULL);
            if (mode & 0x10)
                layout_resize(w, width + 20, height + 10);
        } else {
            free(cause);
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
