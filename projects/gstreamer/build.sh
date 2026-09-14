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
    pushd /tmp
    wget https://archive.ubuntu.com/ubuntu/pool/main/a/autoconf/autoconf_2.71-2_all.deb
    # Ensure file is not modified or corrupted before install
    if echo "96b528889794c4134015a63c75050f93d8aecdf5e3f2a20993c1433f4c61b80e autoconf_2.71-2_all.deb" | sha256sum --check --status ; then
        # Install but use G option to prevent downgrade in case this is
        dpkg -i -G /tmp/autoconf_2.71-2_all.deb
    fi
    popd
fi

$SRC/gstreamer/ci/fuzzing/build-oss-fuzz.sh

# Append structured seeds (see generate_seeds.py). The upstream fuzz targets
# ship with only a handful of corpus files each (and the push-based `typefind`
# target ships none), so we add structurally valid inputs that reach the
# parsing code directly:
#   gst-codec-utils  H.264/H.265/H.266 PTL, AV1 av1C, Opus headers
#   gst-tag          ID3v1/ID3v2 frames, EXIF IFDs, XMP, Vorbis comments
#   gst-subparse     SubRip/WebVTT/MicroDVD/SubViewer/MPL2/SAMI/...
#   typefind         magic headers for many container/codec formats
# Existing corpora are retained; generated seeds are merged into the zips.
python3 $SRC/generate_seeds.py $SRC/generated_seeds
for target in gst-codec-utils gst-tag gst-subparse typefind gst-discoverer; do
  seeddir="$SRC/generated_seeds/$target"
  if [ -d "$seeddir" ]; then
    zip -j -q "$OUT/${target}_seed_corpus.zip" "$seeddir"/*
  fi
done

for ft in gst-tag; do
  echo "[libfuzzer]" > $OUT/${ft}.options
  echo "detect_leaks=0" >> $OUT/${ft}.options
done
