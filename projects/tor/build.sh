#!/bin/bash -eu

sh autogen.sh

./configure --disable-asciidoc
make clean
make -j$(nproc) all
