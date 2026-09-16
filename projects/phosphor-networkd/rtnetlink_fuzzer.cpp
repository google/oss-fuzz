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

#include "netlink.hpp"
#include "rtnetlink.hpp"
#include "types.hpp"

#include <cstddef>
#include <cstdint>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size == 0)
    {
        return 0;
    }

    std::string_view input(reinterpret_cast<const char*>(data), size);

    // 1. Test intfFromRtm
    try
    {
        (void)phosphor::network::netlink::intfFromRtm(input);
    }
    catch (...)
    {
    }

    // 2. Test addrFromRtm
    try
    {
        (void)phosphor::network::netlink::addrFromRtm(input);
    }
    catch (...)
    {
    }

    // 3. Test neighFromRtm
    try
    {
        (void)phosphor::network::netlink::neighFromRtm(input);
    }
    catch (...)
    {
    }

    // 4. Test gatewayFromRtm
    try
    {
        (void)phosphor::network::netlink::gatewayFromRtm(input);
    }
    catch (...)
    {
    }

    // 5. Test extractRtAttr in a loop
    {
        std::string_view attrInput = input;
        while (!attrInput.empty())
        {
            try
            {
                auto [hdr, attrData] =
                    phosphor::network::netlink::extractRtAttr(attrInput);
                (void)hdr;
                (void)attrData;
            }
            catch (...)
            {
                break;
            }
        }
    }

    // 6. Test detail::processMsg
    {
        std::string_view msgInput = input;
        bool done = true;
        auto cb = [](const nlmsghdr&, std::string_view) {};
        try
        {
            phosphor::network::netlink::detail::processMsg(msgInput, done, cb);
        }
        catch (...)
        {
        }
    }

    return 0;
}
