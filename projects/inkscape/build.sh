#!/bin/bash -eu
nproc=$(nproc)

#mysteriously missing lpthread from some linking calls
OLDCFLAGS=${CFLAGS}
OLDCXXFLAGS=${CXXFLAGS}
OLDSANITIZER=${SANITIZER}
OLDCOVERAGE_FLAGS=${COVERAGE_FLAGS}
CFLAGS="-lpthread"
CXXFLAGS="-lpthread -stdlib=libc++ -std=c++11" #libstdc++ ?
SANITIZER=""
COVERAGE_FLAGS=""
cd ../graphite && cmake . -DBUILD_SHARED_LIBS=OFF -DCMAKE_INSTALL_PREFIX=/usr && make -j${nproc} install
cd ../libsigc++* && ./configure --prefix=/usr --enable-static  && make -j${nproc} && make install
cd ../glib2* && ./configure --prefix=/usr --enable-static  && make -j${nproc} && make install
cd ../cairomm* && ./configure --prefix=/usr --enable-static  && make -j${nproc} && make install
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
cd ../dbus* && ./configure --prefix=/usr --enable-static && make -j${nproc} && make install
cd ../inkscape #at long last
ldconfig
mkdir build
cd build
CFLAGS=${OLDCFLAGS}
CXXFLAGS=${OLDCXXFLAGS}
SANITIZER=${OLDSANITIZER}
COVERAGE_FLAGS=${OLDCOVERAGE_FLAGS}
cmake .. -DWITH_FUZZ=ON -DLIB_FUZZING_ENGINE=ON -DCMAKE_BUILD_TYPE=Debug -DCMAKE_INSTALL_PREFIX:PATH=$PWD/install_dir/ -DBUILD_SHARED_LIBS=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DENABLE_LCMS=OFF -DENABLE_POPPLER=OFF -DENABLE_POPPLER_CAIRO=OFF -DWITH_IMAGE_MAGICK=OFF -DWITH_LIBCDR=OFF -DWITH_LIBVISIO=OFF -DWITH_LIBWPG=OFF -DWITH_LPETOOL=OFF -DWITH_NLS=OFF -DWITH_OPENMP=OFF -DWITH_YAML=OFF
make -j$(nproc) inkscape_base
cd testfiles/

#compile
clang++ -I/src/inkscape/build/testfiles -I/src/inkscape/testfiles -I/src/inkscape -I/src/inkscape/src -I/src/inkscape/build/include \
    -isystem /usr/include/pango-1.0 -isystem /usr/include/cairo -isystem /usr/include/pixman-1 -isystem /usr/include/libpng12 -isystem /usr/include/harfbuzz -isystem /usr/include/freetype2 -isystem /usr/include/libsoup-2.4 -isystem /usr/include/libxml2 -isystem /usr/include/glib-2.0 -isystem /usr/lib/x86_64-linux-gnu/glib-2.0/include -isystem /usr/include/gc -isystem /usr/include/dbus-1.0 -isystem /usr/lib/x86_64-linux-gnu/dbus-1.0/include -isystem /usr/include/gio-unix-2.0 -isystem /usr/include/gtkmm-3.0 -isystem /usr/lib/gtkmm-3.0/include -isystem /usr/include/atkmm-1.6 -isystem /usr/include/gtk-3.0/unix-print -isystem /usr/include/gdkmm-3.0 -isystem /usr/lib/gdkmm-3.0/include -isystem /usr/include/giomm-2.4 -isystem /usr/lib/giomm-2.4/include -isystem /usr/include/pangomm-1.4 -isystem /usr/lib/pangomm-1.4/include -isystem /usr/include/glibmm-2.4 -isystem /usr/lib/glibmm-2.4/include -isystem /usr/include/cairomm-1.0 -isystem /usr/lib/cairomm-1.0/include -isystem /usr/include/sigc++-2.0 -isystem /usr/lib/sigc++-2.0/include -isystem /usr/include/libgdl-3.0 -isystem /usr/include/gtk-3.0 -isystem /usr/include/at-spi2-atk/2.0 -isystem /usr/include/at-spi-2.0 -isystem /usr/include/atk-1.0 -isystem /usr/include/gdk-pixbuf-2.0 -isystem /usr/src/gmock/gtest/include -isystem /usr/src/gmock/include -isystem /src/inkscape/gtest/gtest/include  \
    ${CXXFLAGS} \
    -pthread -std=c++11 -stdlib=libc++ -g -fPIE   -pthread -UWITH_LPETOOL -ULPE_ENABLE_TEST_EFFECTS -fPIC -o CMakeFiles/fuzz.dir/fuzzer.cpp.o -c /src/inkscape/testfiles/fuzzer.cpp

#link
clang++  -O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -stdlib=libc++ -std=c++11\
    -Wl,-Bstatic CMakeFiles/fuzz.dir/fuzzer.cpp.o -o fuzz \
    -Wl,--start-group ../src/libinkscape_base.a ../src/libnrtype/libnrtype_LIB.a ../src/libcroco/libcroco_LIB.a ../src/libavoid/libavoid_LIB.a ../src/libcola/libcola_LIB.a ../src/libvpsc/libvpsc_LIB.a ../src/livarot/liblivarot_LIB.a ../src/libuemf/libuemf_LIB.a ../src/2geom/lib2geom_LIB.a ../src/libdepixelize/libdepixelize_LIB.a ../src/util/libutil_LIB.a ../src/inkgc/libgc_LIB.a /usr/lib/*.a \
    -lgraphite2 -lXdmcp -lXau -lxcb -licuuc -licudata -lthai -ldatrie -lc++ -lc -lsepol -lmount -lblkid -lrt -luuid -lutil -lxkbcommon -lrt -lpixman-1 -lpng12 -lexpat -llzma -lcrypt -lgsl -lgc -lxslt -ljpeg -lgslcblas -lgthread-2.0 -lresolv -lcairo-gobject -lXfixes -lXi -lXrandr -lXrender -lXinerama -lXft -lXfixes -lXext -lXdamage -lXcomposite -lXcursor -lX11 -lXext -lz -lm -ldl -lpcre -lxml2 -lcairo -lfontconfig -lfreetype -lpng -lpango-1.0 -lffi -lpangocairo-1.0 -lpangoft2-1.0 -lharfbuzz -ldbus-1 -Wl,--end-group \
    -Wl,-Bdynamic -lgcc_s -lgcc -lselinux -lpthread -lsystemd \
    -fsanitize=address -fsanitize-address-use-after-scope 

cp fuzz $OUT/

