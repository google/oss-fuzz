/*
 * Copyright 2026 Google LLC
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
#include <string.h>

#include <netlink/netlink.h>
#include <netlink/attr.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    struct nlattr *attrs[64];
    memset(attrs, 0, sizeof(attrs));

    /* Treat fuzz input as a raw stream of netlink attributes */
    nla_parse(attrs, 63, (struct nlattr *)data, (int)size, NULL);
    nla_validate((const struct nlattr *)data, (int)size, 63, NULL);
    nla_find((const struct nlattr *)data, (int)size, 1);
    nla_find((const struct nlattr *)data, (int)size, 0xffff);

    return 0;
}
