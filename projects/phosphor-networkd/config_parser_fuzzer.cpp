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

#include "config_parser.hpp"
#include "util.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string_view>
#include <unistd.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size == 0)
    {
        return 0;
    }

    char temp_file[] = "/tmp/fuzz_conf_XXXXXX";
    int fd = mkstemp(temp_file);
    if (fd < 0)
    {
        return 0;
    }

    ssize_t written = write(fd, data, size);
    close(fd);
    if (written < 0)
    {
        unlink(temp_file);
        return 0;
    }

    try
    {
        phosphor::network::config::Parser parser(temp_file);

        // Inspect parser state
        (void)parser.getFileExists();
        (void)parser.getFilename();
        (void)parser.getWarnings();

        // Exercise map queries
        (void)parser.map.getLastValueString("Match", "Name");
        (void)parser.map.getLastValueString("Network", "DHCP");
        (void)parser.map.getLastValueString("DHCP", "ClientIdentifier");
        (void)parser.map.getLastValueString("Address", "Address");
        (void)parser.map.getLastValueString("Route", "Gateway");
        (void)parser.map.getValueStrings("Match", "Name");
        (void)parser.map.getValueStrings("Network", "DHCP");
        (void)parser.map.getValueStrings("DHCP", "ClientIdentifier");

        // Exercise network util config queries
        (void)phosphor::network::getIPv6AcceptRA(parser);
        (void)phosphor::network::getDHCPValue(parser);
        (void)phosphor::network::getDHCPProp(
            parser, phosphor::network::DHCPType::v4, "UseDNS");
        (void)phosphor::network::getDHCPProp(
            parser, phosphor::network::DHCPType::v6, "UseDNS");
        (void)phosphor::network::getDHCPProp(
            parser, phosphor::network::DHCPType::v4, "UseNTP");
        (void)phosphor::network::getDHCPProp(
            parser, phosphor::network::DHCPType::v6, "UseNTP");
        (void)phosphor::network::getDHCPProp(
            parser, phosphor::network::DHCPType::v4, "UseHostname");
        (void)phosphor::network::getDHCPProp(
            parser, phosphor::network::DHCPType::v6, "UseHostname");
        (void)phosphor::network::getDHCPProp(
            parser, phosphor::network::DHCPType::v4, "SendHostname");
        (void)phosphor::network::getDHCPProp(
            parser, phosphor::network::DHCPType::v6, "SendHostname");
        (void)phosphor::network::getDHCPProp(
            parser, phosphor::network::DHCPType::v4, "UseDomains");
        (void)phosphor::network::getDHCPProp(
            parser, phosphor::network::DHCPType::v6, "UseDomains");

        // Round-trip write and re-parse test
        char out_file[] = "/tmp/fuzz_conf_out_XXXXXX";
        int out_fd = mkstemp(out_file);
        if (out_fd >= 0)
        {
            close(out_fd);
            try
            {
                parser.writeFile(out_file);
                phosphor::network::config::Parser re_parser(out_file);
            }
            catch (...)
            {
            }
            unlink(out_file);
        }
    }
    catch (...)
    {
    }

    unlink(temp_file);

    // Direct string helper fuzzing
    std::string_view sv(reinterpret_cast<const char*>(data), size);
    (void)phosphor::network::config::parseBool(sv);
    (void)phosphor::network::config::icaseeq(sv, "true");
    (void)phosphor::network::config::icaseeq(sv, "yes");
    (void)phosphor::network::config::icaseeq(sv, "false");
    (void)phosphor::network::config::icaseeq(sv, "no");

    try
    {
        phosphor::network::config::KeyCheck{}(sv);
    }
    catch (...)
    {
    }

    try
    {
        phosphor::network::config::SectionCheck{}(sv);
    }
    catch (...)
    {
    }

    try
    {
        phosphor::network::config::ValueCheck{}(sv);
    }
    catch (...)
    {
    }

    try
    {
        (void)phosphor::network::config::pathForIntfConf("/etc/systemd/network",
                                                         sv);
        (void)phosphor::network::config::pathForIntfDev("/etc/systemd/network",
                                                        sv);
    }
    catch (...)
    {
    }

    return 0;
}
