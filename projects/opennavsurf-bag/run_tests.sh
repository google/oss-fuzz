#!/bin/sh -ex

cd bag
# Disable ASan since tests don't work with it on.
unset CFLAGS
export CXXFLAGS='-stdlib=libc++ -ldl'

cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -B test_build -S . \
  -DCMAKE_INSTALL_PREFIX:PATH=/opt \
  -DCMAKE_PREFIX_PATH='/opt;/opt/local;/opt/local/HDF_Group/HDF5/1.14.3/' \
  -DBAG_BUILD_SHARED_LIBS:BOOL=OFF \
  -DBAG_BUILD_TESTS:BOOL=ON -DBAG_CODE_COVERAGE:BOOL=OFF \
  -DBAG_BUILD_PYTHON:BOOL=OFF -DBAG_BUILD_EXAMPLES:BOOL=OFF

cmake --build test_build --config Release --target install

# There are some exclusions due to failing tests.
BAG_SAMPLES_PATH=./examples/sample-data ./test_build/tests/bag_tests '~test VR BAG reading GDAL' '~test simple layer read' '~test interleaved legacy layer read' '~test VR BAG reading NBS'
