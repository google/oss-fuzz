#!/bin/bash -eu
# Copyright 2017 Google Inc.
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

# gstreamer requires autoconf 2.71 minimum which is not available in the Ubuntu 20 base image
# Skip this step if a newer base image is used
if grep -q -F "20.04" /etc/os-release ; then
    cd /tmp
    wget https://archive.ubuntu.com/ubuntu/pool/main/a/autoconf/autoconf_2.71-2_all.deb
    # Ensure file is not modified or corrupted before install
    if echo "96b528889794c4134015a63c75050f93d8aecdf5e3f2a20993c1433f4c61b80e autoconf_2.71-2_all.deb" | sha256sum --check --status ; then
        # Install but use G option to prevent downgrade in case this is
        dpkg -i -G /tmp/autoconf_2.71-2_all.deb
    fi
fi


$SRC/gstreamer/ci/fuzzing/build-oss-fuzz.sh
