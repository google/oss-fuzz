// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////
/*
 * libFuzzer target for the MP4 pseudo-streaming module,
 * src/http/modules/ngx_http_mp4_module.c.
 *
 * Unlike the network parsers, mp4 input is a *file on disk* plus two query
 * arguments (?start=, ?end=). The attacker is whoever can place a file under
 * an "mp4" location -- a real, if narrower, scenario -- and then request byte
 * ranges of it. The dangerous code is not the atom reader (its entry-count
 * checks carry the (uint64_t) cast that stops the multiply from wrapping),
 * but the crop/update pass: ngx_http_mp4_crop_stts/stsc/stco/... walk the
 * sample tables using a sample index derived from start/length and index one
 * table with counts taken from another (stsc chunk ids vs. stco entries,
 * stsz sizes vs. sample counts). Every historical mp4 CVE lives in that
 * cross-table trust.
 *
 * This harness drives the whole pipeline the way ngx_http_mp4_handler() does:
 *
 *   - the file bytes are written to an anonymous memfd, so the module's own
 *     ngx_read_file()/pread() path runs unmodified against a real fd; buffer
 *     growth to mp4_max_buffer_size happens for real.
 *   - a minimal ngx_http_request_t supplies only what the process path
 *     touches: r->pool, r->main (== r), and r->loc_conf[mp4->ctx_index].
 *   - the first 8 input bytes become ?start=/?end= (mp4->start / mp4->length),
 *     so the fuzzer explores crop offsets against the same moov; the rest is
 *     the file, prefixed so an ftyp/mdat/moov skeleton is cheap to reach.
 *
 * mp4->file.log and the pool log are zeroed with log_level 0, so the real
 * ngx_log_error_core linked from the tree short-circuits before dereferencing
 * a log file that does not exist.
 */

#define _GNU_SOURCE
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#include "../http/modules/ngx_http_mp4_module.c"


static ngx_log_t  fuzz_log;   /* log_level 0 -> every ngx_log_* is skipped */
static int        fuzz_fd = -1;


static uint32_t
get32(const uint8_t *p)
{
    return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16)
         | ((uint32_t) p[2] << 8) | (uint32_t) p[3];
}


int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    off_t                    fsize;
    uint32_t                 start, length;
    ssize_t                  n;
    void                    *loc_conf[1];
    ngx_pool_t              *pool;
    ngx_http_request_t       r;
    ngx_http_mp4_file_t      mp4;
    ngx_http_mp4_conf_t      conf;

    /* 8 header bytes steer the crop, the remainder is the mp4 file */
    if (size < 8) {
        return 0;
    }

    start = get32(data);
    length = get32(data + 4);
    data += 8;
    size -= 8;

    /* keep the file bounded so buffer growth stays cheap during fuzzing */
    if (size > (1u << 20)) {
        size = 1u << 20;
    }

    if (fuzz_fd < 0) {
        fuzz_fd = memfd_create("mp4fuzz", 0);
        if (fuzz_fd < 0) {
            return 0;
        }
    }

    if (ftruncate(fuzz_fd, 0) != 0) {
        return 0;
    }

    if (size) {
        n = pwrite(fuzz_fd, data, size, 0);
        if (n < 0 || (size_t) n != size) {
            return 0;
        }
    }

    fsize = (off_t) size;

    pool = ngx_create_pool(4096, &fuzz_log);
    if (pool == NULL) {
        return 0;
    }

    /* conf: small starting buffer so the enlarge-to-max path runs; max is
     * capped well below nginx's 10m default to bound fuzzer RSS. */
    ngx_memzero(&conf, sizeof(conf));
    conf.buffer_size = 512;
    conf.max_buffer_size = 4 * 1024 * 1024;
    conf.start_key_frame = 0;

    /* the module ships with ctx_index unset; pin it so
     * ngx_http_get_module_loc_conf(r, mp4) resolves to loc_conf[0]. */
    ngx_http_mp4_module.ctx_index = 0;
    loc_conf[0] = &conf;

    ngx_memzero(&r, sizeof(r));
    r.pool = pool;
    r.main = &r;                      /* last_buf = (r == r->main) -> 1 */
    r.loc_conf = loc_conf;

    ngx_memzero(&mp4, sizeof(mp4));
    mp4.file.fd = fuzz_fd;
    mp4.file.log = &fuzz_log;
    mp4.file.name.len = 7;
    mp4.file.name.data = (u_char *) "mp4fuzz";
    mp4.end = fsize;
    mp4.start = (ngx_uint_t) start;
    /* length 0 means "to end"; only set a window when it is non-zero so both
     * the ?start=only and ?start=&end= shapes get exercised. */
    mp4.length = (ngx_uint_t) length;
    mp4.request = &r;

    (void) ngx_http_mp4_process(&mp4);

    ngx_destroy_pool(pool);

    return 0;
}
