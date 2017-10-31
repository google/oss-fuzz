#!/bin/bash -eu
nproc=$(nproc)

#mysteriously missing lpthread from some linking calls
OLDCFLAGS=${CFLAGS}
OLDCXXFLAGS=${CXXFLAGS}
OLDSANITIZER=${SANITIZER}
OLDCOVERAGE_FLAGS=${COVERAGE_FLAGS}
CFLAGS="-lpthread"
CXXFLAGS="-lpthread"
SANITIZER=""
COVERAGE_FLAGS=""
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
CFLAGS=${OLDCFLAGS}
CXXFLAGS=${OLDCXXFLAGS}
SANITIZER=${OLDSANITIZER}
COVERAGE_FLAGS=${OLDCOVERAGE_FLAGS}
cmake .. -DWITH_FUZZ=ON -DLIB_FUZZING_ENGINE=ON -DCMAKE_BUILD_TYPE=Debug -DCMAKE_INSTALL_PREFIX:PATH=$PWD/install_dir/ -DBUILD_SHARED_LIBS=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DENABLE_LCMS=OFF -DENABLE_POPPLER=OFF -DENABLE_POPPLER_CAIRO=OFF -DWITH_IMAGE_MAGICK=OFF -DWITH_LIBCDR=OFF -DWITH_LIBVISIO=OFF -DWITH_LIBWPG=OFF -DWITH_LPETOOL=OFF -DWITH_NLS=OFF -DWITH_OPENMP=OFF -DWITH_YAML=OFF
make -j$(nproc) inkscape_base
VERBOSE=1 make fuzz
#cd testfiles && /usr/local/bin/clang++    -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -O1 -fno-omit-frame-pointer -gline-tables-only -lpthread -pthread -std=c++11 -g   CMakeFiles/fuzz.dir/fuzzer.cpp.o  -o ../bin/fuzz -rdynamic ../src/libinkscape_base.a -lFuzzingEngine ../src/libnrtype/libnrtype_LIB.a ../src/libcroco/libcroco_LIB.a ../src/libavoid/libavoid_LIB.a ../src/libcola/libcola_LIB.a ../src/libvpsc/libvpsc_LIB.a ../src/livarot/liblivarot_LIB.a ../src/libuemf/libuemf_LIB.a ../src/2geom/lib2geom_LIB.a ../src/libdepixelize/libdepixelize_LIB.a ../src/util/libutil_LIB.a ../src/inkgc/libgc_LIB.a -lharfbuzz -lpangocairo-1.0 -lcairo -lpangoft2-1.0 -lpango-1.0 -lfontconfig -lfreetype -lgsl -lgslcblas -lm -Wl,--export-dynamic -lgmodule-2.0 -pthread -lsoup-2.4 -lgio-2.0 -lgobject-2.0 -lglib-2.0 -lharfbuzz -lpangocairo-1.0 -lcairo -lpangoft2-1.0 -lpango-1.0 -lfontconfig -lfreetype -lgsl -lgslcblas -lm -lgmodule-2.0 -lsoup-2.4 -lgio-2.0 -lgobject-2.0 -lglib-2.0 -lc -lgc -ljpeg -lpng -lpopt -lgtkmm-3.0 -latkmm-1.6 -lgdkmm-3.0 -lgiomm-2.4 -lpangomm-1.4 -lglibmm-2.4 -lcairomm-1.0 -lsigc-2.0 -lgdl-3 -lgtk-3 -lgdk-3 -latk-1.0 -lcairo-gobject -lgdk_pixbuf-2.0 -lxslt -lxml2 -lz -lsigc-2.0 -lX11 -lFuzzingEngine -static

cp bin/fuzz $OUT/

