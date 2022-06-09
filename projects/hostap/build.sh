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

export LDO=$CXX
export LDFLAGS="$CXXFLAGS $LIB_FUZZING_ENGINE"
export CFLAGS="$CFLAGS -MMD"

if [[ "$ARCHITECTURE" == "i386" ]]; then
	# Force static link
	rm -v /lib/i386-linux-gnu/libcrypto.so* || :
fi

# Specific to hostap's rules.include: set empty, as we directly set required
# sanitizer flags in CFLAGS and LDFLAGS (above).
export FUZZ_FLAGS=

for target in fuzzing/*; do
  [[ -d "$target" ]] || continue

  if [[ "$SANITIZER" == "dataflow" ]]; then
	  # libcrypto seems to cause problems with 'dataflow' sanitizer.
	  [[ "$target" == "fuzzing/dpp-uri" ]] && continue || :
	  [[ "$target" == "fuzzing/sae" ]] && continue || :
  fi

  (
    cd "$target"
    make clean

    if [[ "$target" == "fuzzing/tls-server" ]]; then
      export CFLAGS="$CFLAGS -DCERTDIR='\"hwsim/auth_serv/\"'"
    fi

    make -j$(nproc) V=1 LIBFUZZER=y
    mv -v "${target##*/}" "${OUT}/"

    if [[ -d 'corpus' ]]; then
      (cd 'corpus' && zip "${OUT}/${target##*/}_seed_corpus.zip" *)
    fi
  )
done

# Copy required data.
cp -a "hwsim" "${OUT}/"
