cd $SRC/giflib-code
./autogen.sh
make
cd ..
for file in $SRC/*.c;
do
    name=$(basename $file .c)
    $CC $CFLAGS -c -I giflib-code/lib ${file} -o ${name}.o
    $CXX $CXXFLAGS -std=c++11 -I giflib-code/lib ${name}.o \
        -o $OUT/${name} -lFuzzingEngine giflib-code/lib/.libs/libgif.a
done
# Place dict and config in OUT
wget -O $OUT/gif.dict \
  https://raw.githubusercontent.com/mirrorer/afl/master/dictionaries/gif.dict \
  &> /dev/null
cp $SRC/*.options $OUT/
find $SRC/giflib-code -iname "*.gif" -exec \
  zip -ujq $OUT/dgif_target_seed_corpus.zip "{}" \;
