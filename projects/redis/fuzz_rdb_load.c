/*
 * Copyright 2025 Google LLC
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

/*
 * OSS-Fuzz harness for Redis RDB file parser.
 * Writes arbitrary input to a temp file and calls rdbLoad().
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Forward declaration to avoid pulling in all of server.h */
int rdbLoad(char *filename, void *rsi, int rdbflags);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 9) return 0;  /* Need at least "REDIS0011" header */

    char tmpfile[] = "/tmp/fuzz_rdb_XXXXXX";
    int fd = mkstemp(tmpfile);
    if (fd < 0) return 0;

    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        unlink(tmpfile);
        return 0;
    }
    close(fd);

    rdbLoad(tmpfile, NULL, 0);

    unlink(tmpfile);
    return 0;
}
