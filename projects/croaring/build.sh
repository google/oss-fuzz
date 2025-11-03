# Copyright 2021 Google LLC
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

mkdir -p build-dir
cd build-dir
cmake -DENABLE_ROARING_TESTS=OFF -DBUILD_SHARED_LIBS=ON ../croaring
make -j$(nproc)
cd ..
$CC $CFLAGS -I./croaring/include -c ./croaring_fuzzer.c -o fuzzer.o
$CC $CFLAGS -fsanitize=fuzzer fuzzer.o -o $OUT/croaring_fuzzer -L./build-dir -lroaring -Wl,-rpath,./build-dir
