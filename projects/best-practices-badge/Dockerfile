# Copyright 2026 The Authors
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
#
# NOTE: "The Authors" in this case are
# the Linux Foundation and the OpenSSF Best Practices badge contributors.
#
# ALTERNATIVE LICENSING NOTICE:
# This file is dual-licensed and is also available
# under the terms of the MIT License.
# You may use this file under the terms of either the Apache 2.0 License
# or the MIT License.
#
# SPDX-License-Identifier: (APACHE-2.0 OR MIT)
#
################################################################################

FROM gcr.io/oss-fuzz-base/base-builder-ruby

# commonmarker ships a pre-built x86_64-linux native gem (backed by Rust/comrak),
# so no Rust toolchain is required in this image.

RUN git clone --depth=1 \
    https://github.com/coreinfrastructure/best-practices-badge.git \
    "$SRC/best-practices-badge"

COPY build.sh "$SRC/"
