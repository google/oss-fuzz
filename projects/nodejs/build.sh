cd node

# Step 1) build all dependencies with non-fuzzer flags.
# Afterwards we will build the specific nodejs core using the 
# correct fuzzer flags.
# Save original flags
ORIG_CFLAGS=$CFLAGS
ORIG_CXXFLAGS=$CXXFLAGS

export CXXFLAGS="-stdlib=libc++"
export CFLAGS=""
export LDFLAGS="-stdlib=libc++"
export LD="clang++"
./configure
make -j4

export CXXFLAGS=${ORIG_CXXFLAGS}
export CFLAGS=${ORIG_CFLAGS}

# Step 2) build libnode with correct fuzzer flags
CMDS='-DV8_DEPRECATION_WARNINGS '
CMDS+='-DV8_IMMINENT_DEPRECATION_WARNINGS '
CMDS+='-D__STDC_FORMAT_MACROS '
CMDS+='-DOPENSSL_NO_PINSHARED '
CMDS+='-DOPENSSL_THREADS '
CMDS+='-DNODE_ARCH="x64" '
CMDS+='-DNODE_PLATFORM="linux" '
CMDS+='-DNODE_WANT_INTERNALS=1 '
CMDS+='-DHAVE_OPENSSL=1 '
CMDS+='-DHAVE_INSPECTOR=1 '
CMDS+='-D__POSIX__ '
CMDS+='-DNODE_HAVE_I18N_SUPPORT=1 '

# Include flags
INCLUDES='-I../src '
INCLUDES+='-I../tools/msvs/genfiles '
INCLUDES+='-I../deps/v8/include '
INCLUDES+='-I../deps/cares/include '
INCLUDES+='-I../deps/uv/include '
INCLUDES+='-I../deps/uvwasi/include '
INCLUDES+='-I../test/cctest '
INCLUDES+='-I../deps/histogram/src '
INCLUDES+='-I../deps/icu-small/source/i18n '
INCLUDES+='-I../deps/icu-small/source/common '
INCLUDES+='-I../deps/zlib '
INCLUDES+='-I../deps/llhttp/include '
INCLUDES+='-I../deps/nghttp2/lib/includes '
INCLUDES+='-I../deps/brotli/c/include '
INCLUDES+='-I../deps/openssl/openssl/include'

cd $SRC/node/src
for target in *cc;
do
    fname=${target:0:-3}
    clang++ ${CXXFLAGS} -o $fname.o $fname.cc $CMDS $INCLUDES -pthread -fno-omit-frame-pointer -fno-rtti -fno-exceptions -std=gnu++1y -MMD -c  || true
    if test -f $fname.o; then
        echo "Moving $fname"
        mv $fname.o ../out/Release/obj.target/libnode/src/$fname.o
    fi;
done

# Create the static archive
cd ../out/Release/obj.target
rm -f ./libnode.a

complete_libs=""
for target in ./libnode/src/api/*.o ./libnode/src/*.o ./libnode/gen/*.o ./libnode/src/large_pages/*.o ./libnode/src/inspector/*.o ./libnode/gen/src/node/inspector/protocol/*.o ./libnode/src/tracing/*.o
do
    complete_libs="$complete_libs $target"
done
ar crsT ./libnode.a $complete_libs


# Step 3, compile and link the fuzzers
cd $SRC/node/src
mkdir fuzzers
cp ../../fuzz_url.cc ./fuzzers/

# Compile the fuzzer
clang++ -o fuzzers/fuzz_url.o fuzzers/fuzz_url.cc $CXXFLAGS $CMDS $INCLUDES -pthread -fno-omit-frame-pointer -fno-rtti -fno-exceptions -std=gnu++1y -MMD -c


# Link the fuzzer
cd $SRC/node/out

GROUP_ARCHIVES="Release/obj.target/cctest/src/node_snapshot_stub.o "
GROUP_ARCHIVES+="Release/obj.target/cctest/src/node_code_cache_stub.o "
GROUP_ARCHIVES+="../src/fuzzers/fuzz_url.o "
GROUP_ARCHIVES+="Release/obj.target/libnode.a "
GROUP_ARCHIVES+="Release/obj.target/deps/histogram/libhistogram.a "
GROUP_ARCHIVES+="Release/obj.target/deps/uvwasi/libuvwasi.a "
GROUP_ARCHIVES+="Release/obj.target/tools/v8_gypfiles/libv8_snapshot.a "
GROUP_ARCHIVES+="Release/obj.target/tools/v8_gypfiles/libv8_libplatform.a "
GROUP_ARCHIVES+="Release/obj.target/tools/icu/libicui18n.a "
GROUP_ARCHIVES+="Release/obj.target/deps/zlib/libzlib.a "
GROUP_ARCHIVES+="Release/obj.target/deps/llhttp/libllhttp.a "
GROUP_ARCHIVES+="Release/obj.target/deps/cares/libcares.a "
GROUP_ARCHIVES+="Release/obj.target/deps/uv/libuv.a "
GROUP_ARCHIVES+="Release/obj.target/deps/nghttp2/libnghttp2.a "
GROUP_ARCHIVES+="Release/obj.target/deps/brotli/libbrotli.a "
GROUP_ARCHIVES+="Release/obj.target/deps/openssl/libopenssl.a "
GROUP_ARCHIVES+="Release/obj.target/tools/icu/libicuucx.a "
GROUP_ARCHIVES+="Release/obj.target/tools/icu/libicudata.a "
GROUP_ARCHIVES+="Release/obj.target/tools/v8_gypfiles/libv8_base_without_compiler.a "
GROUP_ARCHIVES+="Release/obj.target/tools/v8_gypfiles/libv8_libbase.a "
GROUP_ARCHIVES+="Release/obj.target/tools/v8_gypfiles/libv8_libsampler.a "
GROUP_ARCHIVES+="Release/obj.target/tools/v8_gypfiles/libv8_zlib.a "
GROUP_ARCHIVES+="Release/obj.target/tools/v8_gypfiles/libv8_compiler.a "
GROUP_ARCHIVES+="Release/obj.target/tools/v8_gypfiles/libv8_initializers.a"

clang++ -o Release/fuzz_url $LIB_FUZZING_ENGINE $CXXFLAGS -rdynamic \
                        -Wl,--whole-archive \
                        Release/obj.target/deps/zlib/libzlib.a \
                        Release/obj.target/deps/uv/libuv.a \
                        Release/obj.target/tools/v8_gypfiles/libv8_snapshot.a \
                        Release/obj.target/deps/openssl/libopenssl.a \
                        -Wl,-z,noexecstack,-z,relro,-z,now \
                        -Wl,--no-whole-archive -pthread \
                        -Wl,--start-group  $GROUP_ARCHIVES -latomic -lm -ldl -Wl,--end-group

cp Release/fuzz_url $OUT/fuzz_url
