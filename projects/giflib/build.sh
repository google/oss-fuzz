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
$CC $CFLAGS -Wall -c -I giflib-code dgif_target.c -o dgif_target.o
$CXX $CXXFLAGS -std=c++11 -I giflib-code dgif_target.o \
        -o $OUT/dgif_target $LIB_FUZZING_ENGINE giflib-code/libgif.a

# Place dict and config in OUT
wget -O $OUT/gif.dict \
  https://raw.githubusercontent.com/mirrorer/afl/master/dictionaries/gif.dict \
  &> /dev/null
cp $SRC/*.options $OUT/
find $SRC/giflib-code -iname "*.gif" -exec \
  zip -ujq $OUT/dgif_target_seed_corpus.zip "{}" \;
