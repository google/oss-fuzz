#!/bin/bash -eux
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

# Install CodeIntelligenceTesting Go.
## Require at least Go1.4 to boostrap.
git clone --depth=1 -b dev.libfuzzer.18 https://github.com/CodeIntelligenceTesting/go.git /tmp/go-CodeIntelligenceTesting
# Disable tests, at least one of which erroneously fails.
sed -i '/^exec .* tool dist test -rebuild "$@"/ s/./#&/' /tmp/go-CodeIntelligenceTesting/src/run.bash
# ./all.bash has to be run inside the src/ directory.
(cd /tmp/go-CodeIntelligenceTesting/src/; ./all.bash)


# Replace original Go with the one from CodeIntelligenceTesting.
rm -rf /root/.go
mv -f /tmp/go-CodeIntelligenceTesting /root/.go

# Install go114-fuzz-build with the new Go.
rm -rf "$GOPATH/"
mkdir -p "$GOPATH/"
go install github.com/CodeIntelligenceTesting/go114-fuzz-build@latest
ln -s "$GOPATH/bin/go114-fuzz-build" "$GOPATH/bin/go-fuzz"

# Re-install ossfuzz_coverage_runner.go.
wget -O $GOPATH/ossfuzz_coverage_runner.go https://raw.githubusercontent.com/google/oss-fuzz/898bbe41e57f841d15cb9d30bd42105460857386/infra/base-images/base-builder-go/ossfuzz_coverage_runner.go