#/bin/bash -eu
# Copyright 2021 Google LLC.
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

# Removes traces of "inet.af/netaddr"
rm go.mod
rm example_test.go
rm inlining_test.go
sed -i s/' \/\/ import "inet.af\/netaddr"'//g netaddr.go

# Compile fuzzer
compile_go_fuzzer github.com/inetaf/netaddr Fuzz fuzzer

# Build corpus
cd corpus
git clone https://github.com/inetaf/netaddr-corpus
zip $OUT/fuzzer_seed_corpus.zip netaddr-corpus/*
