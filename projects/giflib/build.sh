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
