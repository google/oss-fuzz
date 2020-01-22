cd $SRC
cd zlib
./configure --static
make install -j$(nproc)

cd $SRC
cd libzip
cmake . -DBUILD_SHARED_LIBS=OFF
make install -j$(nproc)

cd $SRC
cd extra-cmake-modules
cmake .
make install -j$(nproc)

cd $SRC
cd qtbase
# add the flags to Qt build too
sed -i -e "s/QMAKE_CXXFLAGS    += -stdlib=libc++/QMAKE_CXXFLAGS    += -stdlib=libc++  $CXXFLAGS\nQMAKE_CFLAGS += $CFLAGS/g" mkspecs/linux-clang-libc++/qmake.conf
sed -i -e "s/QMAKE_LFLAGS      += -stdlib=libc++/QMAKE_LFLAGS      += -stdlib=libc++ -lpthread $CXXFLAGS/g" mkspecs/linux-clang-libc++/qmake.conf
# disable sanitize=vptr for harfbuzz since it compiles without rtti
sed -i -e "s/TARGET = qtharfbuzz/TARGET = qtharfbuzz\nQMAKE_CXXFLAGS += -fno-sanitize=vptr/g" src/3rdparty/harfbuzz-ng/harfbuzz-ng.pro
# make qmake compile faster
sed -i -e "s/MAKE\")/MAKE\" -j$(nproc))/g" configure
./configure --glib=no --libpng=qt -opensource -confirm-license -static -no-opengl -no-icu -platform linux-clang-libc++ -v
cd src
../bin/qmake -o Makefile src.pro
make sub-gui -j$(nproc)

cd $SRC
cd karchive
cmake . -DBUILD_SHARED_LIBS=OFF -DQt5Core_DIR=$SRC/qtbase/lib/cmake/Qt5Core/ -DBUILD_TESTING=OFF
make install -j$(nproc)

cd $SRC
cd kimageformats
HANDLER_TYPES="KraHandler kra
        OraHandler ora
        PCXHandler pcx
        SoftimagePICHandler pic
        PSDHandler psd
        RASHandler ras
        RGBHandler rgb
        TGAHandler tga
        XCFHandler xcf"

echo "$HANDLER_TYPES" | while read class format; do
(
  fuzz_target_name=kimgio_${format}_fuzzer

  $CXX $CXXFLAGS -fPIC -DHANDLER=$class -std=c++11 $SRC/kimgio_fuzzer.cc $SRC/kimageformats/src/imageformats/$format.cpp -o $OUT/$fuzz_target_name -I $SRC/qtbase/include/QtCore/ -I $SRC/qtbase/include/ -I $SRC/qtbase/include//QtGui -I $SRC/kimageformats/src/imageformats/ -I $SRC/karchive/src/ -I $SRC/qtbase/mkspecs/linux-clang-libc++/ -L $SRC/qtbase/lib -lQt5Gui -lQt5Core -lqtlibpng -lqtharfbuzz -lm -lqtpcre2 -ldl -lpthread $LIB_FUZZING_ENGINE /usr/local/lib/libzip.a /usr/local/lib/libz.a -lKF5Archive

  find . -name "*.${format}" | zip -q $OUT/${fuzz_target_name}_seed_corpus.zip -@
)
done
