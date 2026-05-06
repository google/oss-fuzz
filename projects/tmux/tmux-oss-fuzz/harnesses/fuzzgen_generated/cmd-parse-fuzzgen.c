/*
 * cmd-parse-fuzzgen.c - FuzzGen-style harness for tmux command parsing
 *
 * Target: cmd-parse.y (cmd_parse_from_buffer, cmd_parse_from_string)
 *
 * FuzzGen approach:
 * - Structured data consumption patterns
 * - Separate control bytes from payload
 * - API sequence exploration
 * - Context-aware parsing modes
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "tmux.h"

#define FUZZER_MAXLEN 4096

struct event_base *libevent;

/* Simple data provider for structured consumption */
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
    struct data_provider    dp;
    struct cmd_parse_input  pi;
    struct cmd_parse_result *pr;
    uint8_t                 flags_byte;
    uint16_t                payload_len;
    const uint8_t          *payload;
    char                   *input;
    int                     use_buffer;

    if (size < 4)
        return 0;

    dp_init(&dp, data, size);

    /* Consume control bytes */
    flags_byte = dp_consume_byte(&dp);
    use_buffer = flags_byte & 0x01;  /* Bit 0: use buffer vs string API */
    
    payload_len = dp_consume_u16(&dp);
    if (payload_len > FUZZER_MAXLEN)
        payload_len = FUZZER_MAXLEN;
    if (payload_len > dp_remaining(&dp))
        payload_len = dp_remaining(&dp);
    
    if (payload_len == 0)
        return 0;

    /* Get payload */
    payload = dp_consume_bytes(&dp, payload_len);
    
    /* Null-terminate */
    input = malloc(payload_len + 1);
    if (input == NULL)
        return 0;
    memcpy(input, payload, payload_len);
    input[payload_len] = '\0';

    /* Initialize parse input with controlled flags */
    memset(&pi, 0, sizeof(pi));
    pi.flags = (flags_byte & 0x02) ? CMD_PARSE_VERBOSE : 0;
    pi.flags |= (flags_byte & 0x04) ? CMD_PARSE_PARSEONLY : 0;
    pi.flags |= (flags_byte & 0x08) ? CMD_PARSE_NOALIAS : 0;
    pi.file = (flags_byte & 0x10) ? "test.conf" : NULL;
    pi.line = (flags_byte & 0x20) ? 1 : 0;
    pi.item = NULL;
    pi.c = NULL;
    pi.fs = (struct cmd_find_state){ 0 };

    /* Select API based on control byte */
    if (use_buffer) {
        pr = cmd_parse_from_buffer(input, payload_len, &pi);
    } else {
        pr = cmd_parse_from_string(input, &pi);
    }

    /* Handle result */
    if (pr != NULL) {
        switch (pr->status) {
        case CMD_PARSE_SUCCESS:
            if (pr->cmdlist != NULL)
                cmd_list_free(pr->cmdlist);
            break;
        case CMD_PARSE_ERROR:
            free(pr->error);
            break;
        }
    }

    free(input);
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
