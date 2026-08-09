#!/bin/bash -eu
#
# Copyright 2023 Google LLC
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

./autogen.sh
make install-libLTLIBRARIES

# The media libraries has a significant set of dynamic library dependencies,
# and to resolve this we copy them all over.
find /usr/local/lib -name "libffms2.so*" -exec cp "{}" $OUT \;
DYNLIBS_TO_COPY="libavformat.so* libavcodec.so* libavutil.so* libswscale.so* libswresample.so* libxml2.so* libgme.so* libopenmpt.so* libchromaprint.so* libbluray.so* libssh-gcrypt.so* libvpx.so* libwebpmux.so* libwebp.so* librsvg-2.so* libgobject-2.0.so* libglib-2.0.so* libcairo.so* libzvbi.so* libsnappy.so* libaom.so* libcodec2.so* libgsm.so* libmp3lame.so* libopenjp2.so* libopus.so* libshine.so* libspeex.so* libtheoraenc.so* libtheoradec.so* libtwolame.so* libvorbis.so* libvorbisenc.so* libwavpack.so* libx264.so* libx265.so* libxvidcore.so* libva.so* libva-drm.so* libva-x11.so* libvdpau.so* libX11.so* libxcb.so* libdrm.so* libOpenCL.so* libfontconfig.so* libfreetype.so* libpixman-1.so* libpng16.so* libxcb-shm.so* libxcb-render.so* libXrender.so* libXext.so* libmpg123.so* libvorbisfile.so* libcairo-gobject.so* libgdk_pixbuf-2.0.so* libgmodule-2.0.so* libgio-2.0.so* libpangocairo-1.0.so* libpango-1.0.so* libfribidi.so* libthai.so* libharfbuzz.so* libgraphite2.so* libpangoft2-1.0.so* libsoxr.so* libdatrie.so* libogg.so* libXfixes.so* libnuma.so* libXau.so* libXdmcp.so* libbsd.so* libicuuc.so* libicudata.so*"

for dynlibname in $DYNLIBS_TO_COPY; do
  find /usr/lib -name "${dynlibname}" -exec cp {} $OUT \;
done

for f in $SRC/*_fuzzer.cc; do
  fuzzer=$(basename "$f" _fuzzer.cc)
  $CXX $CXXFLAGS -std=c++11 -I$SRC/ffms2/include \
    $SRC/${fuzzer}_fuzzer.cc -o $OUT/${fuzzer}_fuzzer \
    $LIB_FUZZING_ENGINE -lpthread $OUT/libffms2.so \
    $OUT/*.so*

  patchelf --set-rpath '$ORIGIN/' $OUT/${fuzzer}_fuzzer
done
