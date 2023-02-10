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
      # Download and install the latest stable Go.
      wget -q https://storage.googleapis.com/golang/getgo/installer_linux -O $SRC/installer_linux
      chmod +x $SRC/installer_linux
      SHELL="bash" $SRC/installer_linux -version 1.19
      rm $SRC/installer_linux
      # Set up Golang coverage modules.
      printf $(find . -name gocoverage)
      cd $GOPATH/gocoverage && /root/.go/bin/go install ./...
      cd convertcorpus && /root/.go/bin/go install .
      cd /root/.go/src/cmd/cover && /root/.go/bin/go build && mv cover $GOPATH/bin/gotoolcover
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
