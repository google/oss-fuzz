/*
 * style-fuzzgen.c - FuzzGen-style harness for tmux style parsing
 *
 * Target: style.c (style_parse, style_tostring, style_set)
 *
 * FuzzGen approach:
 * - Base cell configuration control
 * - API sequence exploration
 * - Style attribute combination
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "tmux.h"

#define FUZZER_MAXLEN 2048

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

static uint16_t
dp_consume_u16(struct data_provider *dp)
{
    uint16_t val = 0;
    if (dp->pos + 1 < dp->size) {
        val = dp->data[dp->pos] | (dp->data[dp->pos + 1] << 8);
        dp->pos += 2;
    }
    return val;
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

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct data_provider  dp;
    struct style          sy, sy2;
    struct grid_cell      base_gc, result_gc;
    uint8_t               api_select;
    uint8_t               fg_byte, bg_byte, attr_byte;
    uint16_t              payload_len;
    const uint8_t        *payload;
    char                 *style_str;
    const char           *result;
    int                   ret;

    if (size < 8)
        return 0;

    dp_init(&dp, data, size);

    /* Consume control bytes */
    api_select = dp_consume_byte(&dp);
    fg_byte = dp_consume_byte(&dp);
    bg_byte = dp_consume_byte(&dp);
    attr_byte = dp_consume_byte(&dp);
    
    payload_len = dp_consume_u16(&dp);
    if (payload_len > FUZZER_MAXLEN)
        payload_len = FUZZER_MAXLEN;
    if (payload_len > dp_remaining(&dp))
        payload_len = dp_remaining(&dp);
    
    if (payload_len == 0)
        return 0;

    payload = dp_consume_bytes(&dp, payload_len);

    /* Null-terminate */
    style_str = malloc(payload_len + 1);
    if (style_str == NULL)
        return 0;
    memcpy(style_str, payload, payload_len);
    style_str[payload_len] = '\0';

    /* Configure base grid cell from control bytes */
    memcpy(&base_gc, &grid_default_cell, sizeof(base_gc));
    base_gc.fg = fg_byte;
    base_gc.bg = bg_byte;
    base_gc.attr = attr_byte;

    /* Select API sequence */
    switch (api_select % 5) {
    case 0:
        /* Basic style_parse */
        style_set(&sy, &base_gc);
        ret = style_parse(&sy, &base_gc, style_str);
        if (ret == 0) {
            memcpy(&result_gc, &base_gc, sizeof(result_gc));
            /* Skip style_apply - requires option key string */
        }
        break;
    
    case 1:
        /* style_parse + style_tostring roundtrip */
        style_set(&sy, &base_gc);
        ret = style_parse(&sy, &base_gc, style_str);
        if (ret == 0) {
            result = style_tostring(&sy);
            if (result != NULL) {
                /* Parse the result */
                style_set(&sy2, &grid_default_cell);
                style_parse(&sy2, &grid_default_cell, result);
            }
        }
        break;
    
    case 2:
        /* Multiple parses with different bases */
        for (int i = 0; i < 3; i++) {
            base_gc.fg = (fg_byte + i * 10) % 256;
            base_gc.bg = (bg_byte + i * 10) % 256;
            
            style_set(&sy, &base_gc);
            style_parse(&sy, &base_gc, style_str);
        }
        break;
    
    case 3:
        /* style_parse with default cell */
        style_set(&sy, &grid_default_cell);
        ret = style_parse(&sy, &grid_default_cell, style_str);
        if (ret == 0) {
            /* tostring */
            memcpy(&result_gc, &grid_default_cell, sizeof(result_gc));
            result = style_tostring(&sy);
        }
        break;
    
    case 4:
        /* Chained style operations */
        style_set(&sy, &base_gc);
        
        /* Parse first half */
        size_t half = payload_len / 2;
        char *first_half = malloc(half + 1);
        if (first_half != NULL) {
            memcpy(first_half, style_str, half);
            first_half[half] = '\0';
            
            style_parse(&sy, &base_gc, first_half);
            
            /* Parse second half on top */
            style_parse(&sy, &sy.gc, style_str + half);
            
            free(first_half);
        }
        break;
    }

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
