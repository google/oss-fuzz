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
#include <linux/netfilter/nfnetlink.h>

#include <netlink/netlink.h>
#include <netlink/netfilter/ct.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < sizeof(struct nlmsghdr) + sizeof(struct nfgenmsg))
        return 0;

    struct nlmsghdr *nlh = malloc(size);
    if (!nlh)
        return 0;
    memcpy(nlh, data, size);

    if (nlh->nlmsg_len > (uint32_t)size)
        nlh->nlmsg_len = (uint32_t)size;

    struct nfnl_ct *ct = NULL;
    if (nfnlmsg_ct_parse(nlh, &ct) == 0 && ct)
        nfnl_ct_put(ct);

    free(nlh);
    return 0;
}
