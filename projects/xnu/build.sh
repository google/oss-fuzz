#!/bin/bash -eu
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

mkdir $SRC/build
cd $SRC/build

# Fix stub functions that use old-style empty parameter lists () which
# conflict with header declarations in newer clang versions.
cd $SRC/SockFuzzer
sed -i 's/^void zone_view_startup_init() {}/void zone_view_startup_init(struct zone_view_startup_spec *spec) {}/' fuzz/fakes/osfmk_stubs.c
sed -i 's/^void lck_grp_startup_init() {}/void lck_grp_startup_init(struct lck_grp_startup_spec *spec) {}/' fuzz/fakes/osfmk_stubs.c
sed -i 's/^void lck_mtx_assert() {}/void lck_mtx_assert(lck_mtx_t *lck, unsigned int type) {}/' fuzz/fakes/osfmk_stubs.c
sed -i 's/^void lck_mtx_init() {}/void lck_mtx_init(lck_mtx_t *lck, lck_grp_t *grp, lck_attr_t *attr) {}/' fuzz/fakes/osfmk_stubs.c
sed -i 's/^void lck_mtx_lock() {}/void lck_mtx_lock(lck_mtx_t *lck) {}/' fuzz/fakes/osfmk_stubs.c
sed -i 's/^void lck_spin_init() {}/void lck_spin_init(lck_spin_t *lck, lck_grp_t *grp, lck_attr_t *attr) {}/' fuzz/fakes/osfmk_stubs.c
sed -i 's/^void lck_mtx_lock_spin() {}/void lck_mtx_lock_spin(lck_mtx_t *lck) {}/' fuzz/fakes/osfmk_stubs.c
sed -i 's/^void lck_mtx_convert_spin() {}/void lck_mtx_convert_spin(lck_mtx_t *lck) {}/' fuzz/fakes/osfmk_stubs.c
sed -i 's/^void lck_mtx_free() {}/void lck_mtx_free(lck_mtx_t *lck, lck_grp_t *grp) {}/' fuzz/fakes/osfmk_stubs.c
sed -i 's/^void lck_rw_init() {}/void lck_rw_init(lck_rw_t *lck, lck_grp_t *grp, lck_attr_t *attr) {}/' fuzz/fakes/osfmk_stubs.c
sed -i 's/^void lck_mtx_unlock() {}/void lck_mtx_unlock(lck_mtx_t *lck) {}/' fuzz/fakes/osfmk_stubs.c
sed -i 's/^void lck_attr_free() {}/void lck_attr_free(lck_attr_t *attr) {}/' fuzz/fakes/osfmk_stubs.c
sed -i 's/^void lck_attr_setdebug() {}/void lck_attr_setdebug(lck_attr_t *attr) {}/' fuzz/fakes/osfmk_stubs.c

# Fix kernel_debug stub in fake_impls.c
sed -i 's/^void kernel_debug() {}/void kernel_debug(uint32_t debugid, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4, uintptr_t arg5) {}/' fuzz/fakes/fake_impls.c

# Remove -Werror from XNU build flags since the old code triggers many new
# warnings with the current clang version (e.g. single-bit-bitfield-constant-conversion).
sed -i 's/-Werror//' CMakeLists.txt

# Upgrade C++ standard from C++11 to C++17 since the clang FuzzedDataProvider.h
# header requires C++17 features (std::is_integral_v, std::conditional_t, etc.).
sed -i 's/-std=c++11/-std=c++17/g' CMakeLists.txt

cd $SRC/build
cmake -GNinja $SRC/SockFuzzer
ninja

cp $SRC/build/net_fuzzer $OUT
