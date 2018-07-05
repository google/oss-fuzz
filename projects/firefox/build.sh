#!/bin/bash -eu
# Copyright 2018 Google Inc.
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

# Case-sensitive names of internal Firefox fuzzing targets. Edit to add more.
FUZZ_TARGETS=(
  ContentParentIPC
  SdpParser
  StunParser
  # Qcms # needn't be enabled; has its own project with more sanitizers/engines
)

# Firefox object (build) directory.
OBJDIR=$WORK/obj-fuzz

# Firefox fuzzing build configuration.
cat << EOF > mozconfig
ac_add_options --disable-debug
ac_add_options --disable-elf-hack
ac_add_options --disable-jemalloc
ac_add_options --disable-crashreporter
ac_add_options --enable-fuzzing
ac_add_options --enable-optimize=-O1
ac_add_options --enable-debug-symbols=-gline-tables-only
mk_add_options MOZ_OBJDIR=${OBJDIR}
mk_add_options MOZ_MAKE_FLAGS=-j$(nproc)
mk_add_options CFLAGS=
mk_add_options CXXFLAGS=
EOF

if [[ $SANITIZER = "address" ]]
then
cat << EOF >> mozconfig
ac_add_options --enable-address-sanitizer
EOF
fi

# Build! Takes about 15 minutes on a 32 vCPU instance.
./mach build
./mach gtest buildbutdontrun

# Delete unnecessary files from the object dir, then copy it.
# Weighs in at about 3GB afterwards. Could be reduced further.
find $OBJDIR \
  -regextype posix-extended \
  -iregex ".+\.(png|bmp|gif|jpg|mp3|mp4|ivf|mov|o)$" \
  -delete
rm $OBJDIR/toolkit/library/libxul.so # non-gtest
rm -r $OBJDIR/toolkit/library/x86* # build artefacts
cp -R $OBJDIR $OUT

# These are taken from running ldd on libraries build for Firefox, with the
# output manually filtered for libraries which are available on base-runner.
# Patching even some libraries out doesn't work (undefined symbol errors).
REQUIRED_LIBRARIES=(
  libasyncns.so.0
  libatk-1.0.so.0
  libatk-bridge-2.0.so.0
  libatspi.so.0
  libboost_filesystem.so.1.58.0
  libboost_system.so.1.58.0
  libcairo-gobject.so.2
  libcairo.so.2
  libcapnp-0.5.3.so
  libdatrie.so.1
  libdbus-1.so.3
  libdbus-glib-1.so.2
  libepoxy.so.0
  libffi.so.6
  libFLAC.so.8
  libfontconfig.so.1
  libfreetype.so.6
  libgdk-3.so.0
  libgdk_pixbuf-2.0.so.0
  libgio-2.0.so.0
  libglib-2.0.so.0
  libgmodule-2.0.so.0
  libgobject-2.0.so.0
  libgraphite2.so.3
  libgthread-2.0.so.0
  libgtk-3.so.0
  libharfbuzz.so.0
  libICE.so.6
  libjson-c.so.2
  libkj-0.5.3.so
  libmirclient.so.9
  libmircommon.so.7
  libmircore.so.1
  libmirprotobuf.so.3
  libogg.so.0
  libpango-1.0.so.0
  libpangocairo-1.0.so.0
  libpangoft2-1.0.so.0
  libpixman-1.so.0
  libpng12.so.0
  libprotobuf-lite.so.9
  libpulse.so.0
  libpulsecommon-8.0.so
  libSM.so.6
  libsndfile.so.1
  libthai.so.0
  libvorbis.so.0
  libvorbisenc.so.2
  libwayland-client.so.0
  libwayland-cursor.so.0
  libwayland-egl.so.1
  libwrap.so.0
  libX11-xcb.so.1
  libX11.so.6
  libXau.so.6
  libxcb-render.so.0
  libxcb-shm.so.0
  libxcb.so.1
  libXcomposite.so.1
  libXcursor.so.1
  libXdamage.so.1
  libXdmcp.so.6
  libXext.so.6
  libXfixes.so.3
  libXi.so.6
  libXinerama.so.1
  libxkbcommon.so.0
  libXrandr.so.2
  libXrender.so.1
  libXt.so.6
)

mkdir $WORK/apt
chown _apt $WORK/apt # suppress warning message on each file
cd $WORK/apt

# Download packages which have the required library files.
# Note that apt-file is very slow, hence parallel is used.
# Takes only 1-2 minutes on a 32 vCPU instance.
PACKAGES=($(parallel apt-file search -lx "{}$" ::: ${REQUIRED_LIBRARIES[@]}))
apt-get -q download ${PACKAGES[@]}

mkdir $WORK/deb
# Extract downloaded packages.
find $WORK/apt -exec dpkg-deb --extract "{}" $WORK/deb \;

mkdir $OUT/lib
# Move required libraries (and symlinks). Less than 50MB total.
for REQUIRED_LIBRARY in ${REQUIRED_LIBRARIES[@]}
do
  find $WORK/deb -name "${REQUIRED_LIBRARY}*" -exec mv "{}" $OUT/lib \;
done

# Build a wrapper binary for each target to set environment variables.
for FUZZ_TARGET in ${FUZZ_TARGETS[@]}
do
  $CC $CFLAGS -O0 \
    -DFIREFOX_BINARY=$OUT/firefox/firefox \
    -DFUZZ_TARGET=$FUZZ_TARGET \
    -DLIB_PATH=$OUT/lib \
    $SRC/target.c -o $OUT/$FUZZ_TARGET
done
