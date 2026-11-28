# Copyright 2026 Google LLC
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
# NOTE: The "Copyright 2026 Google LLC" above is FALSE. It is NOT TRUE.
# Its actual copyright is by the Linux Foundation and the
# OpenSSF Best Practices badge contributors.
#
# ALTERNATIVE LICENSING NOTICE:
# This file is dual-licensed; it IS available under Apache-2.0,
# and it is also available under the terms of the MIT License.
# You may use this file under the terms of either the Apache 2.0 License
# or the MIT License.
#
# SPDX-License-Identifier: (APACHE-2.0 OR MIT)
#
# This unfortunate situation is because Google uses a precheck filter
# presuming that it's for open source software that Google developed and
# holds the copyright to, even when that is NOT true. Since Google hasn't
# fixed the filter, the recommended solution is the "required string"
# followed by text that explains the real situation.
#
################################################################################

FROM gcr.io/oss-fuzz-base/base-builder-ruby

# commonmarker ships a pre-built x86_64-linux native gem (backed by Rust/comrak),
# so no Rust toolchain is required in this image.

RUN git clone --depth=1 \
    https://github.com/coreinfrastructure/best-practices-badge.git \
    "$SRC/best-practices-badge"

COPY build.sh "$SRC/"
