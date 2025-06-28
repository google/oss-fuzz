: ${LD:="${CXX}"}
: ${LDFLAGS:="${CXXFLAGS}"}  # to make sure we link with sanitizer runtime

cmake_args=(
    -DCMAKE_BUILD_TYPE=Debug
	-DENABLE_SCRIPTING=OFF
	-DENABLE_PLUGINS=OFF
    #-DENABLE_NEW_MPEGTS_OUTPUT=OFF #Used in obs-ffmpeg plugin which is not built
    #-DENABLE_PIPEWIRE=OFF # Plugins are not buit, so this is not needed
	-DENABLE_TESTS=ON
	-DENABLE_UI=OFF
    -DENABLE_FRONTEND=OFF
	-DENABLE_WAYLAND=OFF
    #-DENABLE_RELOCATABLE=ON
	#-DENABLE_PORTABLE_CONFIG=ON
    -DENABLE_STATIC=ON
    -DBUILD_SHARED_LIBS=OFF

    # C compiler
    -DCMAKE_C_COMPILER="${CC}"
    -DCMAKE_C_FLAGS="${CFLAGS}"
    # C++ compiler
    -DCMAKE_CXX_COMPILER="${CXX}"
    -DCMAKE_CXX_FLAGS="${CXXFLAGS}"
    # Linker
    -DCMAKE_LINKER="${LD}"
    -DCMAKE_EXE_LINKER_FLAGS="${LDFLAGS}"
    -DCMAKE_MODULE_LINKER_FLAGS="${LDFLAGS}"
    -DCMAKE_SHARED_LINKER_FLAGS="${LDFLAGS}"
)

# Temporary fixes as libobs is not built as a static library by default
# 1) turn libobs into a STATIC lib
sed -i 's#^add_library(libobs SHARED)#add_library(libobs STATIC)#' libobs/CMakeLists.txt
# 2) only export when NOT static (so the install/export step won’t fail)
sed -i '/^target_export(libobs)$/c\
if(NOT ENABLE_STATIC)\
  target_export(libobs)\
endif()' libobs/CMakeLists.txt
# 3) enable -fPIC on the static lib so it can be linked
sed -i '/add_library(libobs STATIC)/a \
set_target_properties(libobs PROPERTIES POSITION_INDEPENDENT_CODE ON)' libobs/CMakeLists.txt
# 4) build libobs-opengl as a static lib as well
sed -i -e 's#^add_library(libobs-opengl SHARED)#add_library(libobs-opengl STATIC)#' \
       -e '/add_library(libobs-opengl STATIC)/a\
set_target_properties(libobs-opengl PROPERTIES POSITION_INDEPENDENT_CODE ON)' \
       libobs-opengl/CMakeLists.txt


mkdir -p obs-build
cmake -S . -B obs-build "${cmake_args[@]}"
cmake --build obs-build -- -k -j$(nproc)

# Build the fuzz target
$CXX $CXXFLAGS -std=c++17 \
    -I$SRC/obs-studio/libobs \
    -I$SRC/obs-studio/obs-build/libobs \
    $SRC/fuzz_util_bitstream_reader.cpp \
    /src/obs-studio/obs-build/libobs/libobs.a \
    -lpthread -ldl -lm \
    -o $OUT/fuzz_util_bitstream_reader \
    $LIB_FUZZING_ENGINE
