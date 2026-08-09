#!/bin/bash -eu
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

cd xen
./configure --disable-stubdom --disable-pvshim --disable-docs --disable-xen --with-system-qemu
make clang=y -C tools/include
make clang=y -C tools/fuzz/x86_instruction_emulator libfuzzer-harness
cp tools/fuzz/x86_instruction_emulator/libfuzzer-harness $OUT/x86_instruction_emulator

# Runtime coverage collection requires access to source files and symlinks don't work
# Note: xen/lib/x86/*.c was moved to xen/arch/x86/lib/cpu-policy/ in upstream
cp xen/arch/x86/lib/cpu-policy/*.c tools/fuzz/x86_instruction_emulator
cp tools/tests/x86_emulator/*.c tools/fuzz/x86_instruction_emulator
