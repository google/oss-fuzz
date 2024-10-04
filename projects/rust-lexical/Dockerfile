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
FROM gcr.io/oss-fuzz-base/base-builder-rust@sha256:b9a45fecf0d9be6559fca019e90577632242be120ee2d97cec5c2045c1440710
# ! This project was pinned after a clang bump. Please remove the pin, Try to fix any build warnings and errors, as well as runtime errors
# /usr/bin/ld: /src/rust-lexical/fuzz/target/x86_64-unknown-linux-gnu/release/deps/parse_integer_u16-53e4bc89ab30e724.parse_integer_u16.9056e4c0a19617b4-cgu.0.rcgu.o: in function `asan.module_dtor.204':
#          parse_integer_u16.9056e4c0a19617b4-cgu.0:(.text.asan.module_dtor.204[asan.module_dtor]+0x6): undefined reference to `__sancov_gen_.998'

RUN git clone --depth 1 https://github.com/Alexhuszagh/rust-lexical
COPY build.sh $SRC/
