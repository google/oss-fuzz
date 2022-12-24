# Copyright 2022 Google LLC
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
cd $SRC/cloud-hypervisor
cargo fuzz build -O
cp $SRC/cloud-hypervisor/fuzz/target/x86_64-unknown-linux-gnu/release/balloon $OUT/
cp $SRC/cloud-hypervisor/fuzz/target/x86_64-unknown-linux-gnu/release/block $OUT/
cp $SRC/cloud-hypervisor/fuzz/target/x86_64-unknown-linux-gnu/release/cmos $OUT/
cp $SRC/cloud-hypervisor/fuzz/target/x86_64-unknown-linux-gnu/release/console $OUT/
cp $SRC/cloud-hypervisor/fuzz/target/x86_64-unknown-linux-gnu/release/http_api $OUT/
cp $SRC/cloud-hypervisor/fuzz/target/x86_64-unknown-linux-gnu/release/iommu $OUT/
cp $SRC/cloud-hypervisor/fuzz/target/x86_64-unknown-linux-gnu/release/linux_loader $OUT/
cp $SRC/cloud-hypervisor/fuzz/target/x86_64-unknown-linux-gnu/release/linux_loader_cmdline $OUT/
cp $SRC/cloud-hypervisor/fuzz/target/x86_64-unknown-linux-gnu/release/mem $OUT/
cp $SRC/cloud-hypervisor/fuzz/target/x86_64-unknown-linux-gnu/release/net $OUT/
cp $SRC/cloud-hypervisor/fuzz/target/x86_64-unknown-linux-gnu/release/pmem $OUT/
cp $SRC/cloud-hypervisor/fuzz/target/x86_64-unknown-linux-gnu/release/qcow $OUT/
cp $SRC/cloud-hypervisor/fuzz/target/x86_64-unknown-linux-gnu/release/rng $OUT/
cp $SRC/cloud-hypervisor/fuzz/target/x86_64-unknown-linux-gnu/release/serial $OUT/
cp $SRC/cloud-hypervisor/fuzz/target/x86_64-unknown-linux-gnu/release/vhdx $OUT/
cp $SRC/cloud-hypervisor/fuzz/target/x86_64-unknown-linux-gnu/release/watchdog $OUT/
