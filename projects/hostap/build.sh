#!/bin/bash -eu
# Copyright 2019 Google Inc.
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

cd 'tests'

# Make seed corpora
(
  # Need clean environment for building test-tls used to create seed corpus.
  unset CC
  unset CXX
  unset CFLAGS
  unset CXXFLAGS
  unset LDFLAGS

  make clean
  make test-tls

  for x in client server; do
    ./test-tls $x write "${WORK}/test-tls-${x}.msg"
    (cd "$WORK" && zip "${OUT}/test-tls-${x}-read_seed_corpus.zip" test-tls-${x}.msg)
  done

  (
    cd p2p-fuzzer
    zip "${OUT}/p2p-fuzzer-proberesp_seed_corpus.zip" proberesp*.dat
    zip "${OUT}/p2p-fuzzer-action_seed_corpus.zip" go*.dat inv*.dat p2ps*.dat
  )

  (cd eapol-fuzzer && zip "${OUT}/eapol-fuzzer_seed_corpus.zip" *.dat)
  (cd ap-mgmt-fuzzer && zip "${OUT}/ap-mgmt-fuzzer_seed_corpus.zip" multi.dat)
  (cd wnm-fuzzer && zip "${OUT}/wnm-fuzzer_seed_corpus.zip" *.dat)

  echo '{"a":[[]],"b":1,"c":"q","d":{"e":[{}]}}' > "${WORK}/test.json"
  (cd "$WORK" && zip "${OUT}/test-json_seed_corpus.zip" *.json)

  # TODO: test-x509
)


make clean
export LDO=$CXX
export LDFLAGS="$CXXFLAGS $LIB_FUZZING_ENGINE"
export CFLAGS="$CFLAGS -DTEST_LIBFUZZER -DCONFIG_NO_STDOUT_DEBUG"

# libFuzzer native targets (enabled via TEST_LIBFUZZER) ------------------

for target in json x509; do
  make test-${target} TEST_FUZZ=y
  mv -v "test-${target}" "${OUT}/"
done

# AFL compatible targets --------------------------------------------------

patch_afl_fuzzer() {
  (
    printf '#include <stddef.h>
char* get_fuzzer_input(const char*, size_t*);
void free_fuzzer_input(void*);
#define os_readfile get_fuzzer_input
#define os_free free_fuzzer_input
'
    cat "$1"
  ) > "${1}_"
  mv "${1}_" "$1"
}

print_ignore_leaks_options() {
  cat <<EOF
[libfuzzer]
detect_leaks = 0
EOF
}

export CFLAGS="$CFLAGS -Dmain=fuzzer_main"

(
  export OBJS="../libfuzzer_entry.o"

  # ap-mgmt-fuzzer
  patch_afl_fuzzer "ap-mgmt-fuzzer/ap-mgmt-fuzzer.c"
  make clean
  CFLAGS="$CFLAGS -DEXTRA_ARGS='\"-m\",'" \
    make -C "ap-mgmt-fuzzer"
  mv -v "ap-mgmt-fuzzer/ap-mgmt-fuzzer" "${OUT}/"

  # wnm-fuzzer
  patch_afl_fuzzer "wnm-fuzzer/wnm-fuzzer.c"
  rm -v "libfuzzer_entry.o"
  make -C "wnm-fuzzer"
  mv -v "wnm-fuzzer/wnm-fuzzer" "${OUT}/"

  # TODO: Investigate leak and remove if not false positive.
  print_ignore_leaks_options > "${OUT}/wnm-fuzzer.options"
)

# The below Makefiles do not honor OBJS.
recompile_libfuzzer_entry() {
  rm -vf "libfuzzer_entry.o"
  $CC $CFLAGS -c -o "libfuzzer_entry.o" "libfuzzer_entry.c"
}

# test-tls variants
(
  export LDFLAGS="$LDFLAGS libfuzzer_entry.o"
  make clean

  # test-tls uses fopen to open the input file.
  sed -i '1i\
#define fopen fopen_fuzzer_input
' "test-tls.c"

  CFLAGS="$CFLAGS -DEXTRA_ARGS=\"server\",\"read\"," \
    recompile_libfuzzer_entry
  make test-tls TEST_FUZZ=y
  mv -v "test-tls" "${OUT}/test-tls-server-read"

  CFLAGS="$CFLAGS -DEXTRA_ARGS=\"client\",\"read\"," \
    recompile_libfuzzer_entry
  make test-tls TEST_FUZZ=y
  mv -v "test-tls" "${OUT}/test-tls-client-read"
)

(
  export LDFLAGS="$LDFLAGS ../libfuzzer_entry.o"

  # eapol-fuzzer
  patch_afl_fuzzer "eapol-fuzzer/eapol-fuzzer.c"
  make -C "eapol-fuzzer" clean
  recompile_libfuzzer_entry
  make -C "eapol-fuzzer"
  mv -v "eapol-fuzzer/eapol-fuzzer" "${OUT}/"

  # p2p-fuzzer variants
  patch_afl_fuzzer "p2p-fuzzer/p2p-fuzzer.c"
  make -C "p2p-fuzzer" clean
  CFLAGS="$CFLAGS -DEXTRA_ARGS=\"action\"," \
    recompile_libfuzzer_entry
  make -C "p2p-fuzzer"
  mv -v "p2p-fuzzer/p2p-fuzzer" "${OUT}/p2p-fuzzer-action"
  CFLAGS="$CFLAGS -DEXTRA_ARGS=\"proberesp\"," \
    recompile_libfuzzer_entry
  make -C "p2p-fuzzer"
  mv -v "p2p-fuzzer/p2p-fuzzer" "${OUT}/p2p-fuzzer-proberesp"
)

# Copy required data.
cp -a "hwsim" "${OUT}/"

