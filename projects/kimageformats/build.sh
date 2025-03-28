#!/bin/bash -eu
# Copyright 2020 Google LLC
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

# build zstd
cd $SRC
cd zstd
cmake -S build/cmake -DBUILD_SHARED_LIBS=OFF
make install -j$(nproc)

# Build zlib
cd $SRC
cd zlib
./configure --static
make install -j$(nproc)

# Build libzip
cd $SRC
cd libzip
cmake . -DBUILD_SHARED_LIBS=OFF
make install -j$(nproc)

# Build bzip2
# Inspired from ../bzip2/build
cd $SRC
tar xzf bzip2-*.tar.gz && rm -f bzip2-*.tar.gz
cd bzip2-*
SRCL=(blocksort.o huffman.o crctable.o randtable.o compress.o decompress.o bzlib.o)

for source in ${SRCL[@]}; do
    name=$(basename $source .o)
    $CC $CFLAGS -c ${name}.c
done
rm -f libbz2.a
ar cq libbz2.a ${SRCL[@]}
cp -f bzlib.h /usr/local/include
cp -f libbz2.a /usr/local/lib

# Build xz
export ORIG_CFLAGS="${CFLAGS}"
export ORIG_CXXFLAGS="${CXXFLAGS}"
unset CFLAGS
unset CXXFLAGS
cd $SRC
cd xz
./autogen.sh --no-po4a --no-doxygen
./configure --enable-static --disable-debug --disable-shared --disable-xz --disable-xzdec --disable-lzmainfo
make install -j$(nproc)
export CFLAGS="${ORIG_CFLAGS}"
export CXXFLAGS="${ORIG_CXXFLAGS}"

cd $SRC
cd qtbase
./configure -no-glib -qt-libpng -qt-pcre -opensource -confirm-license -static -no-opengl -no-icu -platform linux-clang-libc++ -debug -prefix /usr -no-feature-widgets -no-feature-sql -no-feature-network  -no-feature-xml -no-feature-dbus -no-feature-printsupport
cmake --build . --parallel $(nproc)
cmake --install .

# Build extra-cmake-modules
cd $SRC
cd extra-cmake-modules
cmake . -DBUILD_TESTING=OFF
make install -j$(nproc)

cd $SRC
cd karchive
rm -rf poqm
cmake . -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=OFF -DCMAKE_INSTALL_PREFIX=/usr/local
make install -j$(nproc)

# Build JXRlib
cd $SRC
cd jxrlib
make -j$(nproc)

# Build LibRaw
cd $SRC
cd LibRaw
TMP_CFLAGS=$CFLAGS
TMP_CXXFLAGS=$CXXFLAGS
CFLAGS="$CFLAGS -fno-sanitize=function,vptr"
CXXFLAGS="$CXXFLAGS -fno-sanitize=function,vptr"
autoreconf --install
./configure --disable-examples
make -j$(nproc)
make install -j$(nproc)
CFLAGS=$TMP_CFLAGS
CXXFLAGS=$TMP_CXXFLAGS


# Build aom
cd $SRC
cd aom
mkdir build.libavif
cd build.libavif
extra_libaom_flags='-DAOM_MAX_ALLOCABLE_MEMORY=536870912 -DDO_RANGE_CHECK_CLAMP=1'
cmake -DBUILD_SHARED_LIBS=0 -DENABLE_DOCS=0 -DENABLE_EXAMPLES=0 -DENABLE_TESTDATA=0 -DENABLE_TESTS=0 -DENABLE_TOOLS=0 -DCONFIG_PIC=1 -DAOM_TARGET_CPU=generic -DCONFIG_SIZE_LIMIT=1 -DDECODE_HEIGHT_LIMIT=12288 -DDECODE_WIDTH_LIMIT=12288 -DAOM_EXTRA_C_FLAGS="${extra_libaom_flags}" -DAOM_EXTRA_CXX_FLAGS="${extra_libaom_flags}" ..
make -j$(nproc)
make install -j$(nproc)

# Build libavif
cd $SRC
ln -s "$SRC/aom" "$SRC/libavif/ext/"
cd libavif
mkdir build
cd build
CFLAGS="$CFLAGS -fPIC" cmake -DBUILD_SHARED_LIBS=OFF -DAVIF_ENABLE_WERROR=OFF -DAVIF_CODEC_AOM=LOCAL -DAVIF_LIBYUV=OFF ..
make -j$(nproc)

# Build libde265
cd $SRC
cd libde265
cmake -DBUILD_SHARED_LIBS=OFF -DDISABLE_SSE=ON .
make -j$(nproc)
make install -j$(nproc)

# Build openjpeg
cd $SRC
cd openjpeg
mkdir build
cd build
cmake -DBUILD_SHARED_LIBS=OFF -DBUILD_STATIC_LIBS=ON -DBUILD_CODEC=OFF ..
make -j$(nproc)
make install -j$(nproc)

# build openh264
cd $SRC
cd openh264
make USE_ASM=No BUILDTYPE=Debug install-static -j$(nproc)

# Build openexr
cd $SRC
cd openexr
mkdir _build
cd _build
cmake  -DBUILD_SHARED_LIBS=OFF ..
make -j$(nproc)
make install -j$(nproc)

# Build libheif
cd $SRC
cd libheif
#Reduce max width and height to avoid allocating too much memory
sed -i "s/static const int MAX_IMAGE_WIDTH = 32768;/static const int MAX_IMAGE_WIDTH = 8192;/g" libheif/security_limits.h
sed -i "s/static const int MAX_IMAGE_HEIGHT = 32768;/static const int MAX_IMAGE_HEIGHT = 8192;/g" libheif/security_limits.h
mkdir build
cd build
cmake -DBUILD_SHARED_LIBS=OFF -DENABLE_PLUGIN_LOADING=OFF -DWITH_DAV1D=OFF -DWITH_EXAMPLES=OFF -DWITH_LIBDE265=ON -DWITH_RAV1E=OFF -DWITH_RAV1E_PLUGIN=OFF -DWITH_SvtEnc=OFF -DWITH_SvtEnc_PLUGIN=OFF -DWITH_X265=OFF -DWITH_OpenJPEG_DECODER=ON -DWITH_OpenH264_DECODER=ON ..
make -j$(nproc)
make install -j$(nproc)

# Build libjxl
cd $SRC
cd libjxl
mkdir build
cd build
CXXFLAGS="$CXXFLAGS -DHWY_COMPILE_ONLY_SCALAR" cmake -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=OFF -DJPEGXL_ENABLE_BENCHMARK=OFF -DJPEGXL_ENABLE_DOXYGEN=OFF -DJPEGXL_ENABLE_EXAMPLES=OFF -DJPEGXL_ENABLE_JNI=OFF -DJPEGXL_ENABLE_JPEGLI=OFF -DJPEGXL_ENABLE_JPEGLI_LIBJPEG=OFF -DJPEGXL_ENABLE_MANPAGES=OFF -DJPEGXL_ENABLE_OPENEXR=OFF -DJPEGXL_ENABLE_PLUGINS=OFF -DJPEGXL_ENABLE_SJPEG=OFF -DJPEGXL_ENABLE_SKCMS=ON -DJPEGXL_ENABLE_TCMALLOC=OFF -DJPEGXL_ENABLE_TOOLS=OFF -DJPEGXL_ENABLE_FUZZERS=OFF ..
make -j$(nproc) jxl jxl_cms jxl_threads

cd $SRC
cd kimageformats
HANDLER_TYPES="ANIHandler ani
        QAVIFHandler avif
        QDDSHandler dds
        EXRHandler exr
        HDRHandler hdr
        HEIFHandler heif
        JP2Handler jp2
        QJpegXLHandler jxl
        JXRHandler jxr
        KraHandler kra
        OraHandler ora
        PCXHandler pcx
        PFMHandler pfm
        SoftimagePICHandler pic
        PSDHandler psd
        PXRHandler pxr
        QOIHandler qoi
        RASHandler ras
        RAWHandler raw
        RGBHandler rgb
        ScitexHandler sct
        TGAHandler tga
        XCFHandler xcf"

echo "$HANDLER_TYPES" | while read class format; do
(
  fuzz_target_name=kimgio_${format}_fuzzer

  /usr/libexec/moc $SRC/kimageformats/src/imageformats/$format.cpp -o $format.moc
  header=`ls $SRC/kimageformats/src/imageformats/$format*.h`
  /usr/libexec/moc $header -o moc_`basename $header .h`.cpp
  $CXX $CXXFLAGS -fPIC -DHANDLER=$class -std=c++17 $SRC/kimgio_fuzzer.cc $SRC/kimageformats/src/imageformats/$format.cpp $SRC/kimageformats/src/imageformats/scanlineconverter.cpp $SRC/kimageformats/src/imageformats/microexif.cpp -o $OUT/$fuzz_target_name -DJXL_STATIC_DEFINE -DJXL_THREADS_STATIC_DEFINE -DJXL_CMS_STATIC_DEFINE -DINITGUID -I $SRC/kimageformats/src/imageformats/ -I $SRC/libavif/include/ -I $SRC/libjxl/build/lib/include/ -I $SRC/libjxl/lib/include/ -I /usr/local/include/OpenEXR/ -I /usr/local/include/KF6/KArchive/ -I /usr/local/include/openjpeg-2.5 -I /usr/local/include/Imath -I $SRC/jxrlib/common/include -I $SRC/jxrlib/jxrgluelib -I $SRC/jxrlib/image/sys -I /usr/include/QtCore/ -I /usr/include/QtGui/ -I . $SRC/libavif/build/libavif.a /usr/local/lib/libheif.a /usr/local/lib/libde265.a /usr/local/lib/libopenh264.a $SRC/aom/build.libavif/libaom.a $SRC/libjxl/build/lib/libjxl_threads.a $SRC/libjxl/build/lib/libjxl.a $SRC/libjxl/build/lib/libjxl_cms.a $SRC/libjxl/build/third_party/highway/libhwy.a $SRC/libjxl/build/third_party/brotli/libbrotlidec.a $SRC/libjxl/build/third_party/brotli/libbrotlienc.a $SRC/libjxl/build/third_party/brotli/libbrotlicommon.a -lQt6Gui -lQt6Core -lQt6BundledLibpng -lQt6BundledHarfbuzz -lm -lQt6BundledPcre2 -ldl -lpthread $LIB_FUZZING_ENGINE /usr/local/lib/libzip.a /usr/local/lib/libz.a -lKF6Archive /usr/local/lib/libz.a /usr/local/lib/libraw.a /usr/local/lib/libOpenEXR-3_3.a /usr/local/lib/libIex-3_3.a /usr/local/lib/libImath-3_1.a /usr/local/lib/libIlmThread-3_3.a /usr/local/lib/libOpenEXRCore-3_3.a /usr/local/lib/libOpenEXRUtil-3_3.a /usr/local/lib/libopenjp2.a /usr/local/lib/libzstd.a $SRC/jxrlib/build/libjxrglue.a $SRC/jxrlib/build/libjpegxr.a -llzma /usr/local/lib/libbz2.a -lclang_rt.builtins

  # -lclang_rt.builtins in the previous line is a temporary workaround to avoid a linker error "undefined reference to __truncsfhf2". Investigate why this is needed here, but not anywhere else, and possibly remove it.

  find . -name "*.${format}" | zip -q $OUT/${fuzz_target_name}_seed_corpus.zip -@
)
done
