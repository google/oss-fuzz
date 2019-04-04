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
# add the flags to Qt build too, we may as well sanitize Qt too (and also fixes memory sanitizer build)
sed -i -e "s/QMAKE_CXXFLAGS    += -stdlib=libc++/QMAKE_CXXFLAGS    += -stdlib=libc++  $CXXFLAGS/g" mkspecs/linux-clang-libc++/qmake.conf
sed -i -e "s/QMAKE_LFLAGS      += -stdlib=libc++/QMAKE_LFLAGS      += -stdlib=libc++ -lpthread $CXXFLAGS/g" mkspecs/linux-clang-libc++/qmake.conf
# make qmake compile faster TODO
sed -i -e "s/MAKE\")/MAKE\" -j10)/g" configure
# Disable compressing rcc files, triggers a warning in the memory sanitizer that i'm not sure is valid. TODO investigate properly
sed -i -e "s/DEFINES += QT_RCC QT_NO_CAST_FROM_ASCII QT_NO_FOREACH/DEFINES += QT_NO_COMPRESS QT_RCC QT_NO_CAST_FROM_ASCII QT_NO_FOREACH/g" src/tools/rcc/rcc.pro
./configure --glib=no --libpng=qt -opensource -confirm-license -static -no-opengl -no-icu -platform linux-clang-libc++ -v
cd src
../bin/qmake -o Makefile src.pro
make sub-gui -j$(nproc)

cd $SRC
cd karchive
cmake . -DBUILD_SHARED_LIBS=OFF -DQt5Core_DIR=$SRC/qtbase/lib/cmake/Qt5Core/ -DBUILD_TESTING=OFF
make install -j$(nproc)

$CXX $CXXFLAGS -fPIC -std=c++11 $SRC/kimgio_fuzzer.cc $SRC/kimageformats/src/imageformats/kra.cpp $SRC/kimageformats/src/imageformats/ora.cpp $SRC/kimageformats/src/imageformats/pcx.cpp $SRC/kimageformats/src/imageformats/pic.cpp  $SRC/kimageformats/src/imageformats/psd.cpp  $SRC/kimageformats/src/imageformats/ras.cpp  $SRC/kimageformats/src/imageformats/rgb.cpp  $SRC/kimageformats/src/imageformats/tga.cpp $SRC/kimageformats/src/imageformats/xcf.cpp -o $OUT/kimgio_fuzzer -I $SRC/qtbase/include/QtCore/ -I $SRC/qtbase/include/ -I $SRC/qtbase/include//QtGui -I $SRC/kimageformats/src/imageformats/ -I $SRC/karchive/src/ -I $SRC/qtbase/mkspecs/linux-clang-libc++/ -L $SRC/qtbase/lib -lQt5Gui -lQt5Core -lqtlibpng -lqtharfbuzz -lm -lqtpcre2 -ldl -lpthread $LIB_FUZZING_ENGINE /usr/local/lib/libzip.a /usr/local/lib/libz.a -lKF5Archive

zip -qr $OUT/kimgio_fuzzer_seed_corpus.zip $SRC/kimageformats/autotests/read/  $SRC/kimageformats/autotests/write/  $SRC/kimageformats/autotests/pic/
