#!/bin/sh -e

pip3 install meson

# Version of glib in Ubuntu Xenial is too old
pushd $SRC/glib-2.67.6
meson _build \
    -Doss_fuzz=enabled \
    -Dinternal_pcre=true \
    --default-library=static \
    -Db_lundef=false \
    -Dlibmount=disabled
ninja -C _build
ninja -C _build install
popd

./scripts/oss-fuzz/build.sh
