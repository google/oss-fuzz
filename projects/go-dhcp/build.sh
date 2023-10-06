#!/bin/bash -eu
# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

go get github.com/AdamKorcz/go-118-fuzz-build/testing

go get github.com/stretchr/testify/assert@v1.6.1
sed -i '58s/^/\/\//g' dhcpv6/dhcpv6_test.go

compile_native_go_fuzzer github.com/insomniacslk/dhcp/dhcpv4       FuzzDHCPv4    fuzz_DHCPv4
compile_native_go_fuzzer github.com/insomniacslk/dhcp/dhcpv6       FuzzDHCPv6    fuzz_DHCPv6
compile_native_go_fuzzer github.com/insomniacslk/dhcp/rfc1035label FuzzLabel     fuzz_Label
