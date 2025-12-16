#!/bin/bash -eux
# Copyright 2025 Google LLC
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

# Detect Ubuntu version
source /etc/os-release

if [[ "$VERSION_ID" == "20.04" ]]; then
  SWIFT_PACKAGES="wget \
            binutils \
            git \
            gnupg2 \
            libc6-dev \
            libcurl4 \
            libedit2 \
            libgcc-9-dev \
            libpython2.7 \
            libsqlite3-0 \
            libstdc++-9-dev \
            libxml2 \
            libz3-dev \
            pkg-config \
            tzdata \
            uuid-dev \
            zlib1g-dev"
  SWIFT_URL="https://download.swift.org/swift-6.1.3-release/ubuntu2004/swift-6.1.3-RELEASE/swift-6.1.3-RELEASE-ubuntu20.04.tar.gz"
  SWIFT_DIR="swift-6.1.3-RELEASE-ubuntu20_04"
elif [[ "$VERSION_ID" == "24.04" ]]; then
  SWIFT_PACKAGES="wget \
            binutils \
            git \
            gnupg2 \
            libc6-dev \
            libcurl4-openssl-dev \
            libedit2 \
            libgcc-13-dev \
            libncurses-dev \
            libpython3-dev \
            libsqlite3-0 \
            libstdc++-13-dev \
            libxml2-dev \
            libz3-dev \
            pkg-config \
            tzdata \
            zip \
            unzip \
            zlib1g-dev"
  SWIFT_URL="https://download.swift.org/swift-6.1.3-release/ubuntu2404/swift-6.1.3-RELEASE/swift-6.1.3-RELEASE-ubuntu24.04.tar.gz"
  SWIFT_DIR="swift-6.1.3-RELEASE-ubuntu24.04"
else
  echo "Unsupported Ubuntu version: $VERSION_ID"
  exit 1
fi

SWIFT_SYMBOLIZER_PACKAGES="build-essential make cmake ninja-build git python3 g++-multilib binutils-dev zlib1g-dev"
apt-get update && apt install -y $SWIFT_PACKAGES && \
  apt install -y $SWIFT_SYMBOLIZER_PACKAGES --no-install-recommends


wget -q $SWIFT_URL
tar xzf $(basename $SWIFT_URL)
cp -r $SWIFT_DIR/usr/* /usr/
rm -rf $(basename $SWIFT_URL) $SWIFT_DIR

# TODO: Move to a seperate work dir
git clone https://github.com/llvm/llvm-project.git
cd llvm-project
git checkout 63bf228450b8403e0c5e828d276be47ffbcd00d0 # TODO: Keep in sync with base-clang.
git apply ../llvmsymbol.diff --verbose
cmake -G "Ninja" \
    -DLIBCXX_ENABLE_SHARED=OFF \
    -DLIBCXX_ENABLE_STATIC_ABI_LIBRARY=ON \
    -DLIBCXXABI_ENABLE_SHARED=OFF \
    -DCMAKE_BUILD_TYPE=Release \
    -DLLVM_TARGETS_TO_BUILD=X86 \
    -DCMAKE_C_COMPILER=clang \
    -DCMAKE_CXX_COMPILER=clang++ \
    -DLLVM_BUILD_TESTS=OFF \
    -DLLVM_INCLUDE_TESTS=OFF llvm
ninja -j$(nproc) llvm-symbolizer
cp bin/llvm-symbolizer /usr/local/bin/llvm-symbolizer-swift

cd $SRC
rm -rf llvm-project llvmsymbol.diff

# TODO: Cleanup packages
apt-get remove --purge -y wget
apt-get autoremove -y
