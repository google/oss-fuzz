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

#include <netlink/netlink.h>
#include <netlink/msg.h>
#include <netlink/attr.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < sizeof(struct nlmsghdr))
        return 0;

    struct nlmsghdr *nlh = malloc(size);
    if (!nlh)
        return 0;
    memcpy(nlh, data, size);

    /* Clamp nlmsg_len to the actual buffer size */
    if (nlh->nlmsg_len > (uint32_t)size)
        nlh->nlmsg_len = (uint32_t)size;

    struct nl_msg *msg = nlmsg_convert(nlh);
    if (msg) {
        struct nlmsghdr *hdr = nlmsg_hdr(msg);
        struct nlattr *attrs[64];
        memset(attrs, 0, sizeof(attrs));
        nlmsg_parse(hdr, 0, attrs, 63, NULL);
        nlmsg_validate(hdr, 0, 63, NULL);
        nlmsg_find_attr(hdr, 0, 1);
        nlmsg_free(msg);
    }

    free(nlh);
    return 0;
}
