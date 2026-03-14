#!/bin/bash -eu
# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

BUILD=$WORK/build
mkdir -p $BUILD

# Fix deadlock in ssh_scp_fuzzer: the server thread blocks in
# ssh_handle_key_exchange and pthread_join waits forever because the
# sockets are only closed after the join. Shut them down first.
SCP_FUZZER="$SRC/libssh/tests/fuzz/ssh_scp_fuzzer.c"
if [ -f "$SCP_FUZZER" ]; then
    sed -i 's/^cleanup_thread:/cleanup_thread:\n    shutdown(socket_fds[0], SHUT_RDWR);\n    shutdown(socket_fds[1], SHUT_RDWR);/' "$SCP_FUZZER"
fi

pushd $BUILD
CFLAGS="$CFLAGS -Wno-error=declaration-after-statement"
cmake -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
    -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
    -DBUILD_SHARED_LIBS=OFF -DWITH_INSECURE_NONE=ON -DWITH_EXEC=OFF \
    -DUNIT_TESTING=ON -DWITH_EXAMPLES=OFF $SRC/libssh
make "-j$(nproc)"

# Build the shared mock server object (needed by ssh_scp_fuzzer)
MOCK_SRC="$SRC/libssh/tests/fuzz/ssh_server_mock.c"
if [ -f "$MOCK_SRC" ]; then
    $CC $CFLAGS -I$SRC/libssh/include/ -I$SRC/libssh/src/ -I$BUILD/ -I$BUILD/include/ \
        -c "$MOCK_SRC" -O0 -g
fi

fuzzers=$(find $SRC/libssh/tests/fuzz/ -name "*_fuzzer.c")
for f in $fuzzers; do
    fuzzerName=$(basename $f .c)
    echo "Building fuzzer $fuzzerName"
    $CC $CFLAGS -I$SRC/libssh/include/ -I$SRC/libssh/src/ -I$BUILD/ -I$BUILD/include/ \
        -c "$f" -O0 -g

    # Fuzzers that use the mock server need the mock object and pthread
    EXTRA_OBJS=""
    EXTRA_LIBS=""
    if [ -f ssh_server_mock.o ]; then
        case "$fuzzerName" in
            ssh_scp_fuzzer|ssh_sftp_fuzzer)
                EXTRA_OBJS="ssh_server_mock.o"
                EXTRA_LIBS="-lpthread"
                ;;
        esac
    fi

    $CXX $CXXFLAGS $fuzzerName.o $EXTRA_OBJS \
        -o "$OUT/$fuzzerName" -O0 -g \
        $LIB_FUZZING_ENGINE ./src/libssh.a -Wl,-Bstatic -lcrypto -lz -Wl,-Bdynamic $EXTRA_LIBS

    if [ -d "$SRC/libssh/tests/fuzz/${fuzzerName}_corpus" ]; then
        zip -j $OUT/${fuzzerName}_seed_corpus.zip $SRC/libssh/tests/fuzz/${fuzzerName}_corpus/*
        cp $OUT/${fuzzerName}_seed_corpus.zip $OUT/${fuzzerName}_nalloc_seed_corpus.zip
    fi

    cp $OUT/${fuzzerName} $OUT/${fuzzerName}_nalloc
done
popd
