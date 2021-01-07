#!/bin/bash

. multibuild/common_utils.sh

export CONFIGURE_BUILD_SOURCED=1
BUILD_PREFIX="${BUILD_PREFIX:-/usr/local}"
export CPPFLAGS="-I$BUILD_PREFIX/include $CPPFLAGS"
export LIBRARY_PATH="$BUILD_PREFIX/lib:$LIBRARY_PATH"
export PKG_CONFIG_PATH="$BUILD_PREFIX/lib/pkgconfig/:$PKG_CONFIG_PATH"

. multibuild/library_builders.sh
. config.sh

pre_build
