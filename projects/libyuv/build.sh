# First install libjpeg
export CFLAGS="$CFLAGS -fPIC"
export CXXFLAGS="$CXXFLAGS -fPIC"

# Set include flags
export CFLAGS="$CFLAGS -I$PWD -I$PWD/.. "
export CXXFLAGS="$CXXFLAGS -I$PWD -I$PWD/.. "



# Install libyuv,
cd $SRC/libyuv
make libyuv.a -f linux.mk

# Compile the fuzzer
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE -I./include -I./include/libyuv ./source/*.o \
    $SRC/libyuv_rotate_fuzzer.cc -o $OUT/libyuv_rotate_fuzzer

find . -name '*_fuzzer.options' -exec cp -v '{}' $OUT ';'