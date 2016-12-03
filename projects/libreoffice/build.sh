#!/bin/bash -eu

#shuffle CXXFLAGS -stdlib=libc++ arg into CXX as well because we use
#the CXX as the linker and need to pass -stdlib=libc++ to build
export CXX="$CXX -stdlib=libc++"
#similarly force the -fsanitize etc args in as well as pthread to get
#things to link successfully during the build
export LDFLAGS="$CFLAGS -lpthread"

cd $OUT
#build under $OUT cause its the only place without enough space to do so
#build in a sub scratch dir so we can easily throw away the build artifacts
#afterwards
mkdir scratch
cd scratch
$SRC/libreoffice/autogen.sh --with-distro=LibreOfficeOssFuzz

make build-nocheck

#copy in linked dependencies on build platform not in deployment platform
#we need to get --disable-gui working again to drop this clutter
cp /usr/lib/x86_64-linux-gnu/libX11.so.6 instdir/program
cp /usr/lib/x86_64-linux-gnu/libXau.so.6 instdir/program
cp /usr/lib/x86_64-linux-gnu/libXdmcp.so.6 instdir/program
cp /usr/lib/x86_64-linux-gnu/libX11-xcb.so.1 instdir/program
cp /usr/lib/x86_64-linux-gnu/libXext.so.6 instdir/program
cp /usr/lib/x86_64-linux-gnu/libXdamage.so.1 instdir/program
cp /usr/lib/x86_64-linux-gnu/libXfixes.so.3 instdir/program
cp /usr/lib/x86_64-linux-gnu/libxcb.so.1 instdir/program
cp /usr/lib/x86_64-linux-gnu/libxcb-shm.so.0 instdir/program
cp /usr/lib/x86_64-linux-gnu/libxcb-render.so.0 instdir/program
cp /usr/lib/x86_64-linux-gnu/libxcb-glx.so.0 instdir/program
cp /usr/lib/x86_64-linux-gnu/libxcb-dri2.so.0 instdir/program
cp /usr/lib/x86_64-linux-gnu/libxcb-dri3.so.0 instdir/program
cp /usr/lib/x86_64-linux-gnu/libxcb-present.so.0 instdir/program
cp /usr/lib/x86_64-linux-gnu/libxcb-sync.so.1 instdir/program
cp /usr/lib/x86_64-linux-gnu/libxshmfence.so.1 instdir/program
cp /usr/lib/x86_64-linux-gnu/libXrender.so.1 instdir/program
cp /usr/lib/x86_64-linux-gnu/libfontconfig.so.1 instdir/program
cp /usr/lib/x86_64-linux-gnu/libfreetype.so.6 instdir/program
cp /usr/lib/x86_64-linux-gnu/libicu*.so.* instdir/program/
cp /usr/lib/x86_64-linux-gnu/libnss3.so instdir/program/
cp /usr/lib/x86_64-linux-gnu/libnssutil3.so instdir/program/
cp /usr/lib/x86_64-linux-gnu/libsmime3.so instdir/program/
cp /usr/lib/x86_64-linux-gnu/libssl3.so instdir/program/
cp /usr/lib/x86_64-linux-gnu/libnspr4.so instdir/program/
cp /usr/lib/x86_64-linux-gnu/libplds4.so instdir/program/
cp /usr/lib/x86_64-linux-gnu/libplc4.so instdir/program/
cp /usr/lib/x86_64-linux-gnu/libpng12.so.0 instdir/program/
cp /usr/lib/x86_64-linux-gnu/libglapi.so.0 instdir/program
cp /usr/lib/x86_64-linux-gnu/libXxf86vm.so.1 instdir/program
cp /usr/lib/x86_64-linux-gnu/libdrm.so.2 instdir/program
cp /usr/lib/x86_64-linux-gnu/mesa/libGL.so.1 instdir/program

#save the output under instdir, which is what we want to keep
rm -rf ../instdir
mv instdir ..
cd ..
#delete the rest
rm -rf scratch

#infra/base-images/base-runner/test_all just looks for all executables and
#assumes they are fuzzers, so first toggle everything non-executable
for NOT_FUZZER_BINARY in $(find $OUT/ -executable -type f); do
  chmod -x $NOT_FUZZER_BINARY
done

#and then toggle our fuzzers back to executable
chmod +x $OUT/instdir/program/*fuzzer*

#simple fontconfig conf that points to our instdir/share/fonts
cp $SRC/fonts.conf $OUT/instdir/program/fonts.conf

#starting corpuses
cp $SRC/*_seed_corpus.zip $OUT/instdir/program
