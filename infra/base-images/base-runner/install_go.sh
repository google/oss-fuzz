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

# Install go on x86_64, don't do anything on ARM.

case $(uname -m) in
    x86_64)
      # Download and install Go.
      export GOROOT=/root/.go
      wget https://go.dev/dl/go1.25.0.linux-amd64.tar.gz
      mkdir temp-go
      tar -C temp-go/ -xzf go1.25.0.linux-amd64.tar.gz

      mkdir $GOROOT
      mv temp-go/go/* /root/.go/
      rm -rf temp-go

      echo 'Set "GOPATH=/root/go"'
      echo 'Set "PATH=$PATH:/root/.go/bin:$GOPATH/bin"'
      # Set up Golang coverage modules.
      printf $(find . -name gocoverage)
      cd $GOPATH/gocoverage && /root/.go/bin/go install ./...
      cd /root/.go/src/cmd/cover && /root/.go/bin/go build && mv cover $GOPATH/bin/gotoolcover
      pushd /tmp
        git clone --depth=1 https://github.com/AdamKorcz/go-118-fuzz-build --branch=v2
        cd go-118-fuzz-build/cmd/convertLibFuzzerTestcaseToStdLibGo
        /root/.go/bin/go build .
        mv convertLibFuzzerTestcaseToStdLibGo $GOPATH/bin/
      popd
      ;;
    aarch64)
      # Don't install go because installer is not provided.
      echo "Not installing go: aarch64."
      ;;
    *)
      echo "Error: unsupported architecture: $(uname -m)"
      exit 1
      ;;
esac
