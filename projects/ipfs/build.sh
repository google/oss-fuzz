#!/bin/bash -eu
# Copyright 2020 Google Inc.
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

cd fuzz

function compile_ds_fuzzer {
  fuzzer=$1

  if [ $# == 2 ]; then
    rm provider* || true
    DS_PROVIDERS="$2" go generate
  fi

  compile_go_fuzzer github.com/ipfs/go-datastore/fuzz Fuzz $fuzzer
}

compile_ds_fuzzer ipfs_ds_flatfs
compile_ds_fuzzer ipfs_ds_badger "github.com/ipfs/go-ds-badger"
compile_ds_fuzzer ipfs_ds_badger2 "github.com/ipfs/go-ds-badger2"

