#!/bin/bash -eu
nproc=$(nproc)

#mysteriously missing from some linking calls
CFLAGS="${CFLAGS} -lpthread"
CXXFLAGS="${CFLAGS} -lpthread"

cd ../libsigc++* && ./configure --prefix=/usr --enable-static  && make -j${nproc} && make install
cd ../cairomm* && ./configure --prefix=/usr --enable-static  && make -j${nproc} && make install
cd ../glib2* && ./configure --prefix=/usr --enable-static  && make -j${nproc} && make install
cd ../gdk-pixbuf* && ./configure --prefix=/usr --with-x11 --enable-static --enable-introspection=no && make -j${nproc} && make install
cd ../glibmm* && ./configure --prefix=/usr --enable-static  && make -j${nproc} && make install
cd ../atk1* && ./configure --prefix=/usr --enable-static --enable-introspection=no && make -j${nproc} && make install
cd ../libepoxy* && ./configure --prefix=/usr --enable-static  && make -j${nproc} && make install
cd ../at-spi2-core* && ./configure --prefix=/usr --enable-static  && make -j${nproc} && make install
cd ../at-spi2-atk* && ./configure --prefix=/usr --enable-static  && make -j${nproc} && make install
cd ../gtk+* && ./configure --prefix=/usr --enable-x11-backend --sysconfdir=/etc --enable-static --enable-introspection=no && make -j${nproc} && make install
cd ../atkmm* && ./configure --prefix=/usr --enable-static  && make -j${nproc} && make install
cd ../pangomm* && ./configure --prefix=/usr --enable-static  && make -j${nproc} && make install
cd ../gtkmm* && ./configure --prefix=/usr --enable-static  && make -j${nproc} && make install
cd ../gdl-3* && ./configure --prefix=/usr --enable-static  && make -j${nproc} && make install
cd ../inkscape #at long last
ldconfig
mkdir build
cd build
cmake .. -DWITH_FUZZ=ON -DLIB_FUZZING_ENGINE=ON -DCMAKE_BUILD_TYPE=Debug -DCMAKE_INSTALL_PREFIX:PATH=$PWD/install_dir/ -DBUILD_SHARED_LIBS=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DENABLE_LCMS=OFF -DENABLE_POPPLER=OFF -DENABLE_POPPLER_CAIRO=OFF -DWITH_IMAGE_MAGICK=OFF -DWITH_LIBCDR=OFF -DWITH_LIBVISIO=OFF -DWITH_LIBWPG=OFF -DWITH_LPETOOL=OFF -DWITH_NLS=OFF -DWITH_OPENMP=OFF -DWITH_YAML=OFF
make -j$(nproc) inkscape_base
VERBOSE=1 make fuzz

cp bin/fuzz $OUT/

