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

set -o pipefail
set -x

RUNC_PATH=github.com/opencontainers/runc
RUNC_FUZZERS="$SRC/cncf-fuzzing/projects/runc"
CGROUPS_PATH=github.com/opencontainers/cgroups
CGROUPS_SRC="$SRC/opencontainers-cgroups"

cd "$SRC/runc"
rm -rf vendor

compile_go_fuzzer github.com/moby/sys/user FuzzUser user_fuzzer
compile_go_fuzzer "$RUNC_PATH/libcontainer/configs" \
  FuzzUnmarshalJSON configs_fuzzer

python3 "$SRC/prepare_harnesses.py"
cp "$SRC/intelrdt_fuzzer.go" "$RUNC_FUZZERS/intelrdt_fuzzer.go"

gofmt -w \
  "$RUNC_FUZZERS/libcontainer_utils_fuzzer.go" \
  "$RUNC_FUZZERS/fs2_fuzzer.go" \
  "$RUNC_FUZZERS/specconv_fuzzer.go" \
  "$RUNC_FUZZERS/intelrdt_fuzzer.go"

# Prepare the exact opencontainers/cgroups version selected by runc as a
# standalone, writable module. Building it outside runc/vendor avoids treating
# a vendored dependency directory as an independent Go module.
CGROUPS_VERSION="$(go list -m -f '{{.Version}}' "$CGROUPS_PATH")"
CGROUPS_CACHE="$(
  go mod download -json "$CGROUPS_PATH@$CGROUPS_VERSION" |
    python3 -c 'import json, sys; print(json.load(sys.stdin)["Dir"])'
)"

test -n "$CGROUPS_VERSION"
test -d "$CGROUPS_CACHE"

rm -rf "$CGROUPS_SRC"
cp -a "$CGROUPS_CACHE" "$CGROUPS_SRC"
chmod -R u+w "$CGROUPS_SRC"

# Move runc-owned harnesses into the current runc source packages before
# resolving the additional fuzzing dependency.
mv "$RUNC_FUZZERS/libcontainer_utils_fuzzer.go" \
  "$SRC/runc/libcontainer/utils/"
mv "$RUNC_FUZZERS/specconv_fuzzer.go" \
  "$SRC/runc/libcontainer/specconv/"
mv "$RUNC_FUZZERS/intelrdt_fuzzer.go" \
  "$SRC/runc/libcontainer/intelrdt/"
mv "$RUNC_FUZZERS/libcontainer_fuzzer.go" \
  "$SRC/runc/libcontainer/"
mv "$SRC/runc/libcontainer/container_linux_test.go" \
  "$SRC/runc/libcontainer/container_linux_test_fuzz.go"

go get github.com/AdaLogics/go-fuzz-headers
go mod tidy

compile_go_fuzzer "$RUNC_PATH/libcontainer/utils" \
  FuzzstripRoot fuzz_strip_root
compile_go_fuzzer "$RUNC_PATH/libcontainer/specconv" \
  Fuzz specconv_fuzzer
compile_go_fuzzer "$RUNC_PATH/libcontainer/intelrdt" \
  FuzzSetCacheScema set_cache_schema_fuzzer
compile_go_fuzzer "$RUNC_PATH/libcontainer/intelrdt" \
  FuzzParseMonFeatures parse_mon_features_fuzzer
compile_go_fuzzer "$RUNC_PATH/libcontainer" \
  FuzzStateApi state_api_fuzzer

# Build the cgroups-owned harnesses in the standalone module corresponding to
# the exact cgroups version selected by runc.
mv "$RUNC_FUZZERS/fs2_fuzzer.go" "$CGROUPS_SRC/fs2/"
mv "$RUNC_FUZZERS/devices_fuzzer.go" "$CGROUPS_SRC/devices/"
mv "$RUNC_FUZZERS/fscommon_fuzzer.go" "$CGROUPS_SRC/fscommon/"

gofmt -w \
  "$CGROUPS_SRC/fs2/fs2_fuzzer.go" \
  "$CGROUPS_SRC/devices/devices_fuzzer.go" \
  "$CGROUPS_SRC/fscommon/fscommon_fuzzer.go"

cd "$CGROUPS_SRC"

go get github.com/AdaLogics/go-fuzz-headers
go mod tidy

compile_go_fuzzer "$CGROUPS_PATH/fs2" FuzzGetStats get_stats_fuzzer
compile_go_fuzzer "$CGROUPS_PATH/fs2" FuzzCgroupReader cgroup_reader_fuzzer
compile_go_fuzzer "$CGROUPS_PATH/devices" Fuzz devices_fuzzer
compile_go_fuzzer "$CGROUPS_PATH/fscommon" FuzzSecurejoin securejoin_fuzzer
