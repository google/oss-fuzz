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

#include "types.hpp"
#include "util.hpp"

#include <fuzzer/FuzzedDataProvider.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    // 1. Test addrFromBuf with various address families
    int family = fdp.PickValueInArray(
        {AF_INET, AF_INET6, AF_UNSPEC, AF_PACKET, AF_NETLINK, 999});
    std::string buf = fdp.ConsumeRandomLengthString(32);
    try
    {
        (void)phosphor::network::addrFromBuf(family, buf);
    }
    catch (...)
    {
    }

    // 2. Test isIPv6LinkLocal with raw bytes
    if (fdp.remaining_bytes() >= sizeof(stdplus::In6Addr))
    {
        std::vector<uint8_t> in6_raw =
            fdp.ConsumeBytes<uint8_t>(sizeof(stdplus::In6Addr));
        stdplus::In6Addr in6;
        std::memcpy(&in6, in6_raw.data(), sizeof(in6));
        (void)phosphor::network::isIPv6LinkLocal(in6);
    }

    // 3. Test interfaceToUbootEthAddr
    std::string intf = fdp.ConsumeRandomLengthString(64);
    (void)phosphor::network::interfaceToUbootEthAddr(intf);

    // 4. Test parseInterfaces
    std::string intfList = fdp.ConsumeRandomLengthString(128);
    (void)phosphor::network::internal::parseInterfaces(intfList);

    // 5. Test isValidNtpServer
    std::string ntpServer = fdp.ConsumeRandomLengthString(128);
    (void)phosphor::network::internal::isValidNtpServer(ntpServer);

    // 6. Test isHostnameValid
    std::string hostname = fdp.ConsumeRemainingBytesAsString();
    (void)phosphor::network::internal::isHostnameValid(hostname);

    return 0;
}
