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
#include <linux/neighbour.h>
#include <linux/rtnetlink.h>

#include <netlink/netlink.h>
#include <netlink/route/neighbour.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < sizeof(struct nlmsghdr) + sizeof(struct ndmsg))
        return 0;

    struct nlmsghdr *nlh = malloc(size);
    if (!nlh)
        return 0;
    memcpy(nlh, data, size);

    /* rtnl_neigh_parse requires RTM_NEWNEIGH message type */
    nlh->nlmsg_type = RTM_NEWNEIGH;
    if (nlh->nlmsg_len > (uint32_t)size)
        nlh->nlmsg_len = (uint32_t)size;

    struct rtnl_neigh *neigh = NULL;
    if (rtnl_neigh_parse(nlh, &neigh) == 0 && neigh)
        rtnl_neigh_put(neigh);

    free(nlh);
    return 0;
}
