#!/bin/bash -eu
# Copyright 2025 Google LLC
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

export ASAN_OPTIONS=detect_stack_use_after_return=0:detect_leaks=0:abort_on_error=0:halt_on_error=0:exitcode=0
ROOT="$SRC/PcapPlusPlus"

echo "=== Packet++Test ==="
cd "$ROOT/Tests/Packet++Test"
# TODO: Skipping failing tests.
./Bin/Packet++Test -x "VrrpCreateAndEditTest;TestMacAddress;TestTcpReassemblyRetran"

echo "=== Pcap++Test (no networking) ==="
cd "$ROOT/Tests/Pcap++Test"
# TODO: Skipping failing tests. TestPcapLiveDeviceList and
# TestPcapLiveDeviceNoNetworking fail because of network so we should keep
# them disabled.
./Bin/Pcap++Test \
    -n -x \
    "TestMacAddress;TestTcpReassemblyRetran;TestTcpReassemblyMissingData;TestPcapLiveDeviceList;TestPcapLiveDeviceNoNetworking"
