/*
 * utf8-fuzzgen.c - FuzzGen-style harness for tmux UTF-8 handling
 *
 * Target: utf8.c (utf8_open, utf8_append, utf8_isvalid, utf8_strvis, etc.)
 *
 * FuzzGen approach:
 * - API sequence selection
 * - Structured byte generation for UTF-8 sequences
 * - Function call ordering control
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "tmux.h"
#include "compat.h"

#define FUZZER_MAXLEN 1024

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
 * Generate a UTF-8 sequence from control bytes
 */
static size_t
generate_utf8_seq(uint8_t ctrl, uint8_t b1, uint8_t b2, uint8_t b3, uint8_t *out)
{
    switch (ctrl % 6) {
    case 0:
        /* ASCII */
        out[0] = b1 & 0x7F;
        return 1;
    case 1:
        /* 2-byte sequence */
        out[0] = 0xC0 | ((b1 >> 2) & 0x1F);
        out[1] = 0x80 | (b1 & 0x3F);
        return 2;
    case 2:
        /* 3-byte sequence */
        out[0] = 0xE0 | ((b1 >> 4) & 0x0F);
        out[1] = 0x80 | ((b1 << 2) & 0x3C) | ((b2 >> 6) & 0x03);
        out[2] = 0x80 | (b2 & 0x3F);
        return 3;
    case 3:
        /* 4-byte sequence */
        out[0] = 0xF0 | ((b1 >> 6) & 0x07);
        out[1] = 0x80 | ((b1 >> 0) & 0x3F);
        out[2] = 0x80 | ((b2 >> 2) & 0x3F);
        out[3] = 0x80 | ((b2 << 4) & 0x30) | (b3 & 0x0F);
        return 4;
    case 4:
        /* Invalid: overlong 2-byte */
        out[0] = 0xC0;
        out[1] = 0x80 | (b1 & 0x3F);
        return 2;
    case 5:
        /* Raw bytes */
        out[0] = b1;
        out[1] = b2;
        out[2] = b3;
        return 3;
    }
    return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct data_provider  dp;
    struct utf8_data      ud;
    uint8_t               api_select;
    uint8_t               seq_count;
    char                  buffer[FUZZER_MAXLEN];
    wchar_t               wc;
    size_t                buf_pos = 0;
    int                   i;

    if (size < 4)
        return 0;

    dp_init(&dp, data, size);

    /* Consume control bytes */
    api_select = dp_consume_byte(&dp);
    seq_count = dp_consume_byte(&dp) % 64 + 1;  /* 1-64 sequences */

    /* Generate UTF-8 buffer from structured input */
    for (i = 0; i < seq_count && buf_pos < FUZZER_MAXLEN - 4; i++) {
        uint8_t ctrl = dp_consume_byte(&dp);
        uint8_t b1 = dp_consume_byte(&dp);
        uint8_t b2 = dp_consume_byte(&dp);
        uint8_t b3 = dp_consume_byte(&dp);
        
        uint8_t seq[4];
        size_t seq_len = generate_utf8_seq(ctrl, b1, b2, b3, seq);
        
        if (buf_pos + seq_len >= FUZZER_MAXLEN)
            break;
        memcpy(buffer + buf_pos, seq, seq_len);
        buf_pos += seq_len;
    }
    buffer[buf_pos] = '\0';

    /* Select API to test based on control byte */
    switch (api_select % 5) {
    case 0:
        /* Test utf8_isvalid */
        utf8_isvalid(buffer);
        break;
    
    case 1:
        /* Test utf8_strvis */
        {
            char *vis_buf = malloc(buf_pos * 4 + 1);
            if (vis_buf != NULL) {
                utf8_strvis(vis_buf, buffer, buf_pos, VIS_OCTAL);
                free(vis_buf);
            }
        }
        break;
    
    case 2:
        /* Test utf8_open/append cycle */
        for (i = 0; i < (int)buf_pos; i++) {
            enum utf8_state state = utf8_open(&ud, buffer[i]);
            if (state == UTF8_MORE) {
                while (++i < (int)buf_pos) {
                    state = utf8_append(&ud, buffer[i]);
                    if (state != UTF8_MORE)
                        break;
                }
            }
        }
        break;
    
    case 3:
        /* Test utf8_towc */
        utf8_set(&ud, 0);
        if (buf_pos >= 4) {
            memcpy(ud.data, buffer, 4);
            ud.size = 4;
            utf8_towc(&ud, &wc);
        }
        break;
    
    case 4:
        /* Test utf8_from_data/utf8_to_data roundtrip */
        utf8_set(&ud, 0);
        if (buf_pos >= 4) {
            u_int combined;
            struct utf8_data ud2;
            
            memcpy(ud.data, buffer, 4);
            ud.size = 4;
            utf8_from_data(&ud, &combined);
            utf8_to_data(combined, &ud2);
        }
        break;
    }

    /* Always run utf8_cstrhas as secondary test */
    if (buf_pos > 0) {
        utf8_set(&ud, 0);
        ud.data[0] = buffer[0];
        ud.size = 1;
        utf8_cstrhas(buffer, &ud);
    }

    return 0;
}

int
LLVMFuzzerInitialize(__unused int *argc, __unused char ***argv)
{
    return 0;
}
