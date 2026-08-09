# Copyright 2024 Google LLC
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
FROM gcr.io/oss-fuzz-base/base-builder-rust

RUN git clone https://fuchsia.googlesource.com/fuchsia
WORKDIR $SRC/fuchsia/src/starnix/lib/third_party/rust_netlink

COPY build.sh $SRC/
COPY fuzz $SRC/fuchsia/src/starnix/lib/third_party/rust_netlink/fuzz

# Copy Cargo.toml to different modules
COPY cargo.toml/parent $SRC/fuchsia/src/starnix/lib/third_party/rust_netlink/Cargo.toml
COPY cargo.toml/core $SRC/fuchsia/src/starnix/lib/third_party/rust_netlink/netlink_packet_core/Cargo.toml
COPY cargo.toml/generic $SRC/fuchsia/src/starnix/lib/third_party/rust_netlink/netlink_packet_generic/Cargo.toml
COPY cargo.toml/route $SRC/fuchsia/src/starnix/lib/third_party/rust_netlink/netlink_packet_route/Cargo.toml
COPY cargo.toml/sock_diag $SRC/fuchsia/src/starnix/lib/third_party/rust_netlink/netlink_packet_sock_diag/Cargo.toml
COPY cargo.toml/utils $SRC/fuchsia/src/starnix/lib/third_party/rust_netlink/netlink_packet_utils/Cargo.toml
