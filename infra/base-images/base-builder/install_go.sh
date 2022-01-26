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

# Install Go1.4 to bootstrap
GOBOOTSTRAP="/usr/local/go1.4-bootstrap"
mkdir "$GOBOOTSTRAP"
curl -L https://dl.google.com/go/go1.4-bootstrap-20171003.tar.gz | tar -xzf - --directory="$GOBOOTSTRAP" --strip=1
cd "$GOBOOTSTRAP/src"
CGO_ENABLED=0
#go version  # Confirm Go is not installed
./make.bash
export PATH=$PATH:"$GOBOOTSTRAP/bin"
go version  # go version go1.4-bootstrap-20170531 linux/amd64

# Install CodeIntelligenceTesting Go
cd "/usr/local/"
git clone https://github.com/CodeIntelligenceTesting/go.git go-exp
cd "go-exp/src"
git checkout dev.libfuzzer.18
# Disable tests, which fails
sed -i '/^exec .* tool dist test -rebuild "$@"/ s/./#&/' run.bash
./all.bash
GOEXPPATH="/usr/local/go-exp"
export PATH="$GOEXPPATH/bin":$PATH
mkdir -p "/root/go/bin"
ln -s "$GOEXPPATH/bin/go" "/root/go/bin/go"
ln -s "$GOEXPPATH/bin/gofmt" "/root/go/bin/gofmt"
go version  # Verify Go version

go get -u github.com/mdempsky/go114-fuzz-build
ln -s "$GOEXPPATH/bin/go114-fuzz-build" "/root/go/bin/go-fuzz"

# Cleanup
rm -rf $GOBOOTSTRAP

echo 'Set "GOPATH=/root/go"'
echo 'Set "PATH=/root/go/bin:$PATH:/root/.go/bin"'

#GOPATH="/root/go"
#echo 'export PATH="/root/go/bin":$PATH:"/root/.go/bin"' >> ~/.bashrc
#source ~/.bashrc


#cd /tmp
#curl -O https://storage.googleapis.com/golang/getgo/installer_linux
#chmod +x ./installer_linux
#SHELL="bash" ./installer_linux
#rm -rf ./installer_linux

#echo 'Set "GOPATH=/root/go"'
#echo 'Set "PATH=$PATH:/root/.go/bin:$GOPATH/bin"'

#go get -u github.com/mdempsky/go114-fuzz-build
#ln -s $GOPATH/bin/go114-fuzz-build $GOPATH/bin/go-fuzz
