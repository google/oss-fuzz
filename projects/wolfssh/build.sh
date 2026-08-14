#!/bin/bash -eu
# Copyright 2026 Google LLC
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


# Build wolfSSL (dependency of wolfSSH)
cd $SRC/wolfssl
./autogen.sh
./configure \
    --enable-static --disable-shared \
    --enable-ssh --enable-keygen \
    --disable-examples --disable-crypttests \
    --prefix=$SRC/wolfssl/install
make -j"$(nproc)"
make install

# Build wolfSSH
cd $SRC/wolfssh
./autogen.sh
./configure \
    --enable-static --disable-shared \
    --disable-examples \
    --with-wolfssl=$SRC/wolfssl/install
make -j"$(nproc)"

# Generate a C header containing the embedded server private key in DER form.
KEY=$SRC/wolfssh/keys/server-key-rsa.der
python3 - <<PYEOF > $SRC/server_key_rsa.h
import sys
with open("$KEY","rb") as f: data=f.read()
print("/* auto-generated */")
print("#ifndef SERVER_KEY_RSA_H")
print("#define SERVER_KEY_RSA_H")
print("#include <stddef.h>")
print("static const unsigned char server_key_rsa_der[] = {")
for i in range(0,len(data),12):
    print("  " + ", ".join("0x%02x"%b for b in data[i:i+12]) + ",")
print("};")
print("static const size_t server_key_rsa_der_len = sizeof(server_key_rsa_der);")
print("#endif")
PYEOF

# Build the fuzzer harness
$CC $CFLAGS \
    -I$SRC/wolfssl/install/include -I$SRC/wolfssh -I$SRC \
    -c $SRC/ada-fuzzers/projects/wolfssh/fuzzer/fuzz_server.c -o $SRC/fuzz_server.o

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
    $SRC/fuzz_server.o \
    $SRC/wolfssh/src/.libs/libwolfssh.a \
    $SRC/wolfssl/install/lib/libwolfssl.a \
    -o $OUT/fuzz_server

# A minimal SSH dictionary to help the fuzzer hit early protocol tokens.
cat > $OUT/fuzz_server.dict <<'DICT'
"SSH-2.0-"
"SSH-1.99-"
"\x00\x00\x00\x00"
"ssh-rsa"
"ssh-ed25519"
"ecdsa-sha2-nistp256"
"diffie-hellman-group14-sha256"
"diffie-hellman-group14-sha1"
"curve25519-sha256"
"ecdh-sha2-nistp256"
"aes128-ctr"
"aes256-ctr"
"aes128-gcm@openssh.com"
"hmac-sha2-256"
"hmac-sha1"
"none"
"password"
"publickey"
"ssh-connection"
"ssh-userauth"
"session"
DICT

# Seed corpus: a single banner-shaped input to bootstrap coverage.
mkdir -p $SRC/seeds
printf 'SSH-2.0-libssh_0.10\r\n' > $SRC/seeds/banner
(cd $SRC/seeds && zip -q $OUT/fuzz_server_seed_corpus.zip *)
