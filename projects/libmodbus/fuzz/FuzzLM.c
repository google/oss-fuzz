/* Copyright 2026 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
/*
 * fuzz_lm.c - self-designed in-process harness for libmodbus.
 *
 * No listening sockets, no threads: a socketpair() is attached to the context
 * with modbus_set_socket(), so TCP *and* RTU framing can be driven from memory.
 *
 * byte0 selects the mode (mod 8):
 *   0 REPLY-TCP   modbus_reply() on arbitrary-length requests (server handler)
 *   1 REPLY-RTU
 *   2 SERVER-TCP  byte stream -> modbus_receive() -> modbus_reply() loop
 *   3 SERVER-RTU
 *   4 CLIENT-TCP  multi-step client session; fuzzed responses
 *   5 CLIENT-RTU
 *   6 CTOR        constructors / setters that take untrusted strings
 *   7 PROXY       modbus_proxy() gateway; flags bit3 = frontend RTU, bit4 = backend RTU
 * byte1..4 : mapping geometry, byte5: slave id, byte6: option flags.
 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "modbus.h"

static const unsigned NB_TAB[8] = {0, 1, 7, 8, 9, 64, 300, 2100};
static const unsigned START_TAB[4] = {0, 1, 0x20, 65530};

static uint16_t crc16_std(const uint8_t *p, size_t n)
{
    uint16_t crc = 0xFFFF;
    while (n--) {
        crc ^= *p++;
        for (int i = 0; i < 8; i++)
            crc = (crc & 1) ? (crc >> 1) ^ 0xA001 : crc >> 1;
    }
    return crc;
}

typedef struct {
    const uint8_t *p;
    size_t n;
} rd_t;

static int rd_u8(rd_t *r, uint8_t *v)
{
    if (r->n == 0)
        return 0;
    *v = *r->p++;
    r->n--;
    return 1;
}

static const uint8_t *rd_bytes(rd_t *r, size_t len)
{
    const uint8_t *q;
    if (r->n < len)
        len = r->n;
    q = r->p;
    r->p += len;
    r->n -= len;
    return q;
}

static void done(modbus_t *ctx, int peer)
{
    if (ctx) {
        modbus_close(ctx); /* modbus_free() does not close the fd */
        modbus_free(ctx);
    }
    close(peer);
}

static void drain(int fd)
{
    uint8_t scratch[1024];
    while (recv(fd, scratch, sizeof scratch, MSG_DONTWAIT) > 0)
        ;
}

static modbus_t *make_ctx(int rtu, int slave, int flags, int fd)
{
    modbus_t *ctx = rtu ? modbus_new_rtu("/dev/null", 9600, 'N', 8, 1)
                        : modbus_new_tcp("127.0.0.1", 1502);
    if (!ctx) {
        close(fd);
        return NULL;
    }
    modbus_set_slave(ctx, slave);
    /* sleeps in the library use the response timeout: keep them tiny */
    modbus_set_response_timeout(ctx, 0, 1);
    modbus_set_byte_timeout(ctx, 0, 1);
    modbus_set_indication_timeout(ctx, 0, 1);
    unsigned rec = MODBUS_ERROR_RECOVERY_NONE;
    if (flags & 1)
        rec |= MODBUS_ERROR_RECOVERY_LINK;
    if (flags & 2)
        rec |= MODBUS_ERROR_RECOVERY_PROTOCOL;
    /* LINK recovery would reconnect to a real address: only PROTOCOL here */
    modbus_set_error_recovery(ctx, rec & ~MODBUS_ERROR_RECOVERY_LINK);
    if (flags & 4)
        modbus_enable_quirks(ctx, MODBUS_QUIRK_ALL);
    modbus_set_socket(ctx, fd);
    return ctx;
}

static modbus_mapping_t *make_map(const uint8_t *h)
{
    return modbus_mapping_new_start_address(START_TAB[h[3] & 3],
                                            NB_TAB[h[0] & 7],
                                            START_TAB[(h[3] >> 2) & 3],
                                            NB_TAB[(h[0] >> 3) & 7],
                                            START_TAB[(h[3] >> 4) & 3],
                                            NB_TAB[h[1] & 7],
                                            START_TAB[(h[3] >> 6) & 3],
                                            NB_TAB[(h[1] >> 3) & 7]);
}

/* ---------------------------------------------------------------- server */

static void mode_reply(int rtu, const uint8_t *h, int slave, int flags, rd_t *r)
{
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv))
        return;
    modbus_t *ctx = make_ctx(rtu, slave, flags, sv[0]);
    modbus_mapping_t *map = make_map(h);
    if (ctx && map) {
        uint8_t lo, fl;
        int steps = 0;
        while (steps++ < 32 && rd_u8(r, &lo) && rd_u8(r, &fl)) {
            size_t len = lo + ((fl & 2) ? 256 : 0);
            size_t have = len < r->n ? len : r->n;
            const uint8_t *src = rd_bytes(r, len);
            /* exact-size heap copy so ASAN sees any over-read of req */
            uint8_t *req = malloc(have ? have : 1);
            memcpy(req, src, have);
            modbus_reply(ctx, req, (int) have, map);
            /* no length parameter: API contract = caller passes a complete
             * request (slave + function present), so honour that here */
            if ((fl & 1) && have >= (rtu ? 2u : 8u))
                modbus_reply_exception(ctx, req, fl >> 2);
            free(req);
            drain(sv[1]);
        }
    }
    modbus_mapping_free(map);
    done(ctx, sv[1]);
}

static void mode_server(int rtu, const uint8_t *h, int slave, int flags, rd_t *r)
{
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv))
        return;
    size_t n = r->n > 4096 ? 4096 : r->n;
    if (n && send(sv[1], r->p, n, MSG_NOSIGNAL) < 0) {
        close(sv[0]);
        close(sv[1]);
        return;
    }
    shutdown(sv[1], SHUT_WR);
    modbus_t *ctx = make_ctx(rtu, slave, flags, sv[0]);
    modbus_mapping_t *map = make_map(h);
    if (ctx && map) {
        int adu = rtu ? MODBUS_RTU_MAX_ADU_LENGTH : MODBUS_TCP_MAX_ADU_LENGTH;
        uint8_t *query = malloc(adu);
        for (int i = 0; i < 64; i++) {
            int rc = modbus_receive(ctx, query);
            if (rc > 0)
                modbus_reply(ctx, query, rc, map);
            else if (rc < 0)
                break;
            if (i & 1)
                drain(sv[1]);
        }
        free(query);
    }
    modbus_mapping_free(map);
    done(ctx, sv[1]);
}

/* ---------------------------------------------------------------- client */

/* Length (incl. header/checksum) libmodbus expects for a confirmation. */
static size_t expected_conf_len(int rtu, const uint8_t *f, size_t have)
{
    size_t hdr = rtu ? 1 : 7, chk = rtu ? 2 : 0;
    if (have < hdr + 1)
        return hdr + 1;
    int fc = f[hdr], meta;
    switch (fc) {
    case 5: case 6: case 15: case 16: meta = 4; break;
    case 22: meta = 6; break;
    default: meta = 1;
    }
    size_t total = hdr + 1 + meta;
    if (have < total)
        return total + chk;
    if (fc <= 4 || fc == 0x11 || fc == 0x17)
        total += f[hdr + 1];
    return total + chk;
}

#define MAXFRAME 300

static size_t build_frame(int rtu, int fix, int tid_val, int slave,
                          const uint8_t *in, size_t len, uint8_t *out)
{
    memset(out, 0, MAXFRAME);
    memcpy(out, in, len);
    size_t hdr = rtu ? 1 : 7;
    if (!(fix & 1))
        return len; /* raw, exactly what the fuzzer produced */
    size_t total = expected_conf_len(rtu, out, len);
    if (total > MAXFRAME - 2)
        total = MAXFRAME - 2;
    if (rtu) {
        out[0] = slave;
        uint16_t c = crc16_std(out, total - 2);
        out[total - 2] = c & 0xFF;
        out[total - 1] = c >> 8;
    } else {
        uint16_t tid = tid_val;
        out[0] = tid >> 8; out[1] = tid & 0xFF;
        out[2] = out[3] = 0;
        out[4] = ((total - 6) >> 8); out[5] = (total - 6) & 0xFF;
        out[6] = slave;
    }
    (void) hdr;
    return total;
}

typedef struct { uint8_t op, fix, a1, a2, a3, a4, flen; } op_t;

static void mode_client(int rtu, int slave, int flags, rd_t *r)
{
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv))
        return;
    op_t ops[16];
    int nops = 0;
    uint8_t frame[MAXFRAME];

    /* pass 1: decode the op list and queue all responses */
    while (nops < 16 && r->n >= 7) {
        op_t *o = &ops[nops];
        rd_u8(r, &o->op); rd_u8(r, &o->fix);
        rd_u8(r, &o->a1); rd_u8(r, &o->a2); rd_u8(r, &o->a3); rd_u8(r, &o->a4);
        rd_u8(r, &o->flen);
        size_t have = o->flen < r->n ? o->flen : r->n;
        const uint8_t *src = rd_bytes(r, o->flen);
        size_t fl = build_frame(rtu, o->fix, nops + 1, slave, src, have, frame);
        if (fl && send(sv[1], frame, fl, MSG_NOSIGNAL) < 0)
            break;
        nops++;
    }
    shutdown(sv[1], SHUT_WR); /* starved reads end with ECONNRESET, no sleeps */

    modbus_t *ctx = make_ctx(rtu, slave, flags, sv[0]);
    for (int i = 0; ctx && i < nops; i++) {
        op_t *o = &ops[i];
        int raw = o->fix & 2;
        int addr = (o->a1 << 8) | o->a2;
        int v16 = (o->a3 << 8) | o->a4;
        int nb;
#define NB(max) (raw ? v16 : 1 + (v16 % (max)))
        switch (o->op % 12) {
        case 0: case 1: {
            nb = NB(MODBUS_MAX_READ_BITS);
            uint8_t *d = malloc(nb > 0 ? nb : 1);
            (o->op % 12 == 0 ? modbus_read_bits : modbus_read_input_bits)(ctx, addr, nb, d);
            free(d);
        } break;
        case 2: case 3: {
            nb = NB(MODBUS_MAX_READ_REGISTERS);
            uint16_t *d = malloc((nb > 0 ? nb : 1) * 2);
            (o->op % 12 == 2 ? modbus_read_registers : modbus_read_input_registers)(ctx, addr, nb, d);
            free(d);
        } break;
        case 4: modbus_write_bit(ctx, addr, v16 & 1); break;
        case 5: modbus_write_register(ctx, addr, v16); break;
        case 6: {
            nb = NB(MODBUS_MAX_WRITE_BITS);
            uint8_t *s = malloc(nb > 0 ? nb : 1);
            for (int k = 0; k < nb; k++) s[k] = (k * 7 + o->a3) & 1;
            modbus_write_bits(ctx, addr, nb, s);
            free(s);
        } break;
        case 7: {
            nb = NB(MODBUS_MAX_WRITE_REGISTERS);
            uint16_t *s = malloc((nb > 0 ? nb : 1) * 2);
            for (int k = 0; k < nb; k++) s[k] = k * 257 + o->a4;
            modbus_write_registers(ctx, addr, nb, s);
            free(s);
        } break;
        case 8: modbus_mask_write_register(ctx, addr, o->a3 * 257, o->a4 * 257); break;
        case 9: {
            int nbw = 1 + (o->a3 % MODBUS_MAX_WR_WRITE_REGISTERS);
            nb = 1 + (o->a4 % MODBUS_MAX_WR_READ_REGISTERS);
            uint16_t *s = calloc(nbw, 2), *d = malloc(nb * 2);
            modbus_write_and_read_registers(ctx, addr, nbw, s, (addr + 3) & 0xFFFF, nb, d);
            free(s); free(d);
        } break;
        case 10: {
            int mx = o->a3;
            uint8_t *d = malloc(mx ? mx : 1);
            modbus_report_slave_id(ctx, mx, d);
            free(d);
        } break;
        case 11: {
            uint8_t req[16] = {slave, o->a1 % 24, o->a2, o->a3, o->a4, 0, 1, 2, 3, 4};
            uint8_t *rsp = malloc(rtu ? MODBUS_RTU_MAX_ADU_LENGTH : MODBUS_TCP_MAX_ADU_LENGTH);
            if (modbus_send_raw_request(ctx, req, 2 + (o->a1 >> 5)) > 0)
                modbus_receive_confirmation(ctx, rsp);
            free(rsp);
        } break;
        }
        drain(sv[1]);
    }
    done(ctx, sv[1]);
}

/* ----------------------------------------------------------------- proxy */

/* modbus_proxy(): frontend request in, backend response (fuzzed) relayed back.
 * Frontend/backend backends are chosen independently (TCP<->RTU gateway).
 * step = [req_len][fix][req bytes][rsp_len][rsp bytes]; backend TID is 0. */
static void mode_proxy(int slave, int flags, rd_t *r)
{
    int fe_rtu = (flags >> 3) & 1, be_rtu = (flags >> 4) & 1;
    int fsv[2], bsv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fsv))
        return;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, bsv)) {
        close(fsv[0]);
        close(fsv[1]);
        return;
    }
    struct { uint8_t *req; size_t len; } st[8];
    int n = 0;
    uint8_t lo, fix, rl, frame[MAXFRAME];
    while (n < 8 && rd_u8(r, &lo) && rd_u8(r, &fix)) {
        size_t have = lo < r->n ? lo : r->n;
        const uint8_t *src = rd_bytes(r, lo);
        st[n].req = malloc(have ? have : 1);
        memcpy(st[n].req, src, have);
        st[n].len = have;
        n++;
        if (!rd_u8(r, &rl))
            break;
        size_t rhave = rl < r->n ? rl : r->n;
        const uint8_t *rsrc = rd_bytes(r, rl);
        size_t fl = build_frame(be_rtu, fix, 0, slave, rsrc, rhave, frame);
        if (fl && send(bsv[1], frame, fl, MSG_NOSIGNAL) < 0)
            break;
    }
    shutdown(bsv[1], SHUT_WR);
    modbus_t *fe = make_ctx(fe_rtu, slave, flags, fsv[0]);
    modbus_t *be = make_ctx(be_rtu, slave, flags, bsv[0]);
    for (int i = 0; fe && be && i < n; i++) {
        modbus_proxy(fe, be, st[i].req, (int) st[i].len);
        drain(fsv[1]);
        drain(bsv[1]);
    }
    for (int i = 0; i < n; i++)
        free(st[i].req);
    done(fe, fsv[1]);
    done(be, bsv[1]); /* make_ctx() already closed the fd of a failed ctx */
}

/* ------------------------------------------------------------------ ctor */

static char *cstr(rd_t *r, uint8_t len)
{
    size_t have = len < r->n ? len : r->n;
    const uint8_t *p = rd_bytes(r, len);
    char *s = malloc(have + 1);
    memcpy(s, p, have);
    s[have] = 0;
    return s;
}

static void mode_ctor(rd_t *r)
{
    uint8_t k, l1, l2, b1, b2, b3;
    if (!rd_u8(r, &k) || !rd_u8(r, &l1) || !rd_u8(r, &l2) || !rd_u8(r, &b1) ||
        !rd_u8(r, &b2) || !rd_u8(r, &b3))
        return;
    char *s1 = cstr(r, l1), *s2 = cstr(r, l2);
    modbus_t *ctx = NULL;
    switch (k % 3) {
    case 0: ctx = modbus_new_tcp(s1, (b1 << 8) | b2); break;
    case 1: ctx = modbus_new_tcp_pi(s1, s2); break;
    case 2:
        ctx = modbus_new_rtu(s1, (b1 << 8) | b2, b3 & 0x7F, b1 & 15, b2 & 7);
        if (ctx) {
            modbus_rtu_set_serial_mode(ctx, b1 & 3);
            modbus_rtu_set_rts(ctx, b2 & 3);
            modbus_rtu_set_rts_delay(ctx, (b3 << 8) | b1);
            modbus_rtu_get_rts_delay(ctx);
            modbus_rtu_set_custom_rts(ctx, NULL);
        }
        break;
    }
    if (ctx) {
        modbus_set_slave(ctx, (int8_t) b3);
        modbus_set_response_timeout(ctx, b1, b2 * 1000u);
        modbus_set_byte_timeout(ctx, b2, b3);
        modbus_set_indication_timeout(ctx, b3, b1);
        modbus_free(ctx);
    }
    free(s1);
    free(s2);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 8)
        return 0;
    rd_t r = {data, size};
    uint8_t h[8];
    for (int i = 0; i < 7; i++)
        rd_u8(&r, &h[i]);
    int mode = h[0] % 8;
    const uint8_t *g = h + 1; /* geometry bytes g[0..3] */
    int rtu = mode & 1;
    int slave = rtu ? h[5] % 248 : h[5];
    int flags = h[6];
    switch (mode) {
    case 0: case 1: mode_reply(rtu, g, slave, flags, &r); break;
    case 2: case 3: mode_server(rtu, g, slave, flags, &r); break;
    case 4: case 5: mode_client(rtu, slave, flags, &r); break;
    case 6: mode_ctor(&r); break;
    case 7: mode_proxy(slave, flags, &r); break;
    }
    return 0;
}
