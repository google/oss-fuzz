#!/bin/bash -eux
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

# Install CodeIntelligenceTesting Go
#  (require at least Go1.4 to boostrap)
cd /root
git clone --depth=1 -b dev.libfuzzer.18 https://github.com/CodeIntelligenceTesting/go.git .go-CodeIntelligenceTesting
cd .go-CodeIntelligenceTesting/src
# Disable tests, which fails
sed -i '/^exec .* tool dist test -rebuild "$@"/ s/./#&/' run.bash
./all.bash

# Remember to set env in dockerfile before this line
echo 'Set "GOCODEINTELLIGENCETESTINGPATH=/root/go-CodeIntelligenceTesting"'
echo 'Set "PATH=/root/.go-CodeIntelligenceTesting/bin:$GOCODEINTELLIGENCETESTINGPATH/bin:$PATH"'

# Get go114-fuzz-build with the new Go
rm "$GOPATH/bin/go-fuzz"
rm "$GOPATH/bin/go114-fuzz-build"
go mod tidy
go mod vendor
go install github.com/mdempsky/go114-fuzz-build@latest
ln -s "$GOPATH/bin/go114-fuzz-build" "$GOPATH/bin/go-fuzz"

