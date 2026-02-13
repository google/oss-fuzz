#!/bin/bash -eu
cd $SRC/axis2c
exec bash fuzz/oss-fuzz/build.sh
