set -e
SOURCES=(dgif_lib.c egif_lib.c getarg.c gifalloc.c gif_err.c gif_font.c \
        gif_hash.c openbsd-reallocarray.c qprintf.c quantize.c)
cd $SRC/giflib-code
rm -f *.o
for file in ${SOURCES[@]};
do
    name=$(basename $file .c)
    $CC -c -I . $CFLAGS $file -o $name.o
done
ar rc libgif.a *.o

cd $SRC
$CC $CFLAGS $LIB_FUZZING_ENGINE -Wall -c -I giflib-code dgif_target.c -o dgif_target.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE -std=c++11 -I giflib-code dgif_target.o \
        -o $OUT/dgif_target giflib-code/libgif.a

rm -rf genfiles && mkdir genfiles && LPM/external.protobuf/bin/protoc gif_fuzz_proto.proto --cpp_out=genfiles

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE -Wall -c -I giflib-code dgif_protobuf_target.cc -I libprotobuf-mutator/ \
-I genfiles \
-I LPM/external.protobuf/include \
LPM/src/libfuzzer/libprotobuf-mutator-libfuzzer.a \
LPM/src/libprotobuf-mutator.a \
LPM/external.protobuf/lib/libprotobuf.a \
 -o dgif_protobuf_target.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE -std=c++11 -I giflib-code dgif_protobuf_target.o genfiles/gif_fuzz_proto.pb.cc \
ProtoToGif.cpp \
-I LPM/external.protobuf/include \
-I genfiles \
LPM/src/libfuzzer/libprotobuf-mutator-libfuzzer.a \
LPM/src/libprotobuf-mutator.a \
LPM/external.protobuf/lib/libprotobuf.a \
        -o $OUT/dgif_protobuf_target -fsanitize=fuzzer giflib-code/libgif.a
# Place dict and config in OUT
wget -O $OUT/gif.dict \
  https://raw.githubusercontent.com/mirrorer/afl/master/dictionaries/gif.dict \
  &> /dev/null
cp $SRC/*.options $OUT/
find $SRC/giflib-code -iname "*.gif" -exec \
  zip -ujq $OUT/dgif_target_seed_corpus.zip "{}" \;
