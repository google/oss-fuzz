/*
 * format-fuzzgen.c - FuzzGen-style harness for tmux format string expansion
 *
 * Target: format.c (format_expand, format_expand_time, format_create)
 *
 * FuzzGen approach:
 * - Format flag control via structured input
 * - API sequence exploration
 * - Variable injection control
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "tmux.h"

#define FUZZER_MAXLEN 4096

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

/* Variable table for injection */
static const char *var_names[] = {
    "test_var1", "test_var2", "test_var3", "test_var4",
    "pane_id", "window_index", "session_name", "host"
};
#define NUM_VARS (sizeof(var_names) / sizeof(var_names[0]))

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct data_provider  dp;
    struct format_tree   *ft;
    uint8_t               api_select;
    uint8_t               flag_byte;
    uint8_t               var_ctrl;
    uint16_t              payload_len;
    const uint8_t        *payload;
    char                 *format, *result;
    int                   flags;
    int                   i;

    if (size < 6)
        return 0;

    dp_init(&dp, data, size);

    /* Consume control bytes */
    api_select = dp_consume_byte(&dp);
    flag_byte = dp_consume_byte(&dp);
    var_ctrl = dp_consume_byte(&dp);
    
    payload_len = dp_consume_u16(&dp);
    if (payload_len > FUZZER_MAXLEN)
        payload_len = FUZZER_MAXLEN;
    if (payload_len > dp_remaining(&dp))
        payload_len = dp_remaining(&dp);
    
    if (payload_len == 0)
        return 0;

    payload = dp_consume_bytes(&dp, payload_len);

    /* Null-terminate */
    format = malloc(payload_len + 1);
    if (format == NULL)
        return 0;
    memcpy(format, payload, payload_len);
    format[payload_len] = '\0';

    /* Build flags from control byte */
    flags = FORMAT_NONE;
    if (flag_byte & 0x01) flags |= FORMAT_NOJOBS;
    if (flag_byte & 0x02) flags |= FORMAT_VERBOSE;
    if (flag_byte & 0x04) flags |= FORMAT_FORCE;
    if (flag_byte & 0x08) flags |= FORMAT_STATUS;

    /* Create format tree */
    ft = format_create(NULL, NULL, flags, 0);
    if (ft == NULL) {
        free(format);
        return 0;
    }

    /* Add variables based on control byte */
    for (i = 0; i < (int)NUM_VARS; i++) {
        if (var_ctrl & (1 << i)) {
            format_add(ft, var_names[i], "%s", "fuzz_value");
        }
    }

    /* Select API to test */
    switch (api_select % 3) {
    case 0:
        /* format_expand */
        result = format_expand(ft, format);
        if (result != NULL)
            free(result);
        break;
    
    case 1:
        /* format_expand_time */
        result = format_expand_time(ft, format);
        if (result != NULL)
            free(result);
        break;
    
    case 2:
        /* Multiple expansions with same format string */
        for (i = 0; i < 3; i++) {
            result = format_expand(ft, format);
            if (result != NULL)
                free(result);
        }
        break;
    }

    format_free(ft);
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
