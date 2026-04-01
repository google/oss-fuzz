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

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include <netlink/addr.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* nl_addr_parse requires a null-terminated string */
    char *str = malloc(size + 1);
    if (!str)
        return 0;
    memcpy(str, data, size);
    str[size] = '\0';

    static const int families[] = {
        AF_UNSPEC, AF_INET, AF_INET6, AF_LLC
    };

    for (int i = 0; i < 4; i++) {
        struct nl_addr *addr = NULL;
        if (nl_addr_parse(str, families[i], &addr) == 0 && addr)
            nl_addr_put(addr);
    }

    free(str);
    return 0;
}
