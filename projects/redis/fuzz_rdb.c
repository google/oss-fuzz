/* Copyright 2026 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <setjmp.h>

#include "fmacros.h"
#include "server.h"

/* Declared in server.c */
void createSharedObjects(void);

/* Declared in module.c */
extern void moduleInitModulesSystem(void);

/* We intercept exit() to prevent the fuzzer from dying.
 * rdb.c calls exit(1) on certain error paths via rdbReportError. */
static jmp_buf fuzz_jmpbuf;
static int fuzz_active = 0;

void __wrap_exit(int status) {
    if (fuzz_active) {
        longjmp(fuzz_jmpbuf, 1);
    }
    _exit(status);
}

/* Cap allocations at 64MB to prevent OOM from rdbLoadLen-decoded sizes.
 * The RDB variable-length encoding can pack 64-bit values into a few bytes,
 * so even tiny fuzz inputs can request multi-GB allocations. */
#define FUZZ_MAX_ALLOC (64 * 1024 * 1024)
void *__wrap_malloc(size_t size) {
    extern void *__real_malloc(size_t);
    if (size > FUZZ_MAX_ALLOC) return NULL;
    return __real_malloc(size);
}
void *__wrap_calloc(size_t nmemb, size_t size) {
    extern void *__real_calloc(size_t, size_t);
    if (nmemb > 0 && size > FUZZ_MAX_ALLOC / nmemb) return NULL;
    return __real_calloc(nmemb, size);
}
void *__wrap_realloc(void *ptr, size_t size) {
    extern void *__real_realloc(void *, size_t);
    if (size > FUZZ_MAX_ALLOC) return NULL;
    return __real_realloc(ptr, size);
}

static int initialized = 0;

static void fuzz_init(void) {
    if (initialized) return;
    initialized = 1;

    server.verbosity = LL_NOTHING;

    if (shared.integers[0] == NULL)
        createSharedObjects();

    moduleInitModulesSystem();

    server.loading_process_events_interval_bytes = 0;
    server.sanitize_dump_payload = SANITIZE_DUMP_YES;
    server.loading = 0;
    server.hz = 10;
    server.dbnum = 16;
    server.maxmemory_policy = 0;
}

/* Fuzz the RDB file format parser. RDB is Redis's persistence format
 * and is also used in replication and the RESTORE command. This is a
 * critical attack surface as malformed RDB data can come from:
 * - Disk (compromised or corrupted dump files)
 * - Network (replication from a malicious master)
 * - Client commands (RESTORE with crafted payload) */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 9 || size > 1024 * 1024 * 10) return 0;

    fuzz_init();

    sds buf = sdsnewlen(data, size);
    if (!buf) return 0;

    rio rdb;
    rioInitWithBuffer(&rdb, buf);

    fuzz_active = 1;
    if (setjmp(fuzz_jmpbuf) == 0) {
        char hdr[10];
        if (rioRead(&rdb, hdr, 9)) {
            hdr[9] = '\0';
            if (memcmp(hdr, "REDIS", 5) == 0) {
                int rdbver = atoi(hdr + 5);
                if (rdbver >= 1 && rdbver <= RDB_VERSION) {
                    int type;
                    while ((type = rdbLoadType(&rdb)) != -1) {
                        if (type == RDB_OPCODE_EOF) break;
                        if (type == RDB_OPCODE_SELECTDB) {
                            rdbLoadLen(&rdb, NULL);
                            continue;
                        } else if (type == RDB_OPCODE_EXPIRETIME) {
                            rdbLoadTime(&rdb);
                            continue;
                        } else if (type == RDB_OPCODE_EXPIRETIME_MS) {
                            rdbLoadMillisecondTime(&rdb, rdbver);
                            continue;
                        } else if (type == RDB_OPCODE_FREQ) {
                            uint8_t byte;
                            rioRead(&rdb, &byte, 1);
                            continue;
                        } else if (type == RDB_OPCODE_IDLE) {
                            rdbLoadLen(&rdb, NULL);
                            continue;
                        } else if (type == RDB_OPCODE_RESIZEDB) {
                            rdbLoadLen(&rdb, NULL);
                            rdbLoadLen(&rdb, NULL);
                            continue;
                        } else if (type == RDB_OPCODE_AUX) {
                            robj *auxkey = rdbLoadStringObject(&rdb);
                            robj *auxval = rdbLoadStringObject(&rdb);
                            if (auxkey) decrRefCount(auxkey);
                            if (auxval) decrRefCount(auxval);
                            continue;
                        }
                        /* For data types, load key + value */
                        if (type >= 0 && type <= 24) {
                            robj *keyobj = rdbLoadStringObject(&rdb);
                            if (keyobj) {
                                sds key = keyobj->ptr;
                                int error;
                                robj *val = rdbLoadObject(type, &rdb, key, 0, &error);
                                if (val) decrRefCount(val);
                                decrRefCount(keyobj);
                            }
                        }
                        break; /* Parse one object per call to avoid infinite loops */
                    }
                }
            }
        }
    }
    fuzz_active = 0;

    sdsfree(buf);
    return 0;
}
