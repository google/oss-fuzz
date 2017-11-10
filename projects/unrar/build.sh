#!/bin/bash -eu
# Copyright 2017 Google Inc.
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

set -eu

tar xf $SRC/unrarsrc-5.5.8.tar.gz

# build 'lib'. This builds libunrar.a and libunrar.so
# -fPIC is required for successful compilation.
make CXX=$CXX CXXFLAGS="$CXXFLAGS -fPIC" -C $SRC/unrar/unrar lib

# remove the .so file so that the linker links unrar statically.
rm -v $SRC/unrar/unrar/libunrar.so

cat <<HERE > $SRC/unrar/unrar_fuzzer.cc
#include <memory>
#include <stddef.h>
#include <string>
#include <unistd.h>

#include "unrar/rar.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  char filename[] = "mytemp.XXXXXX";
  int fd = mkstemp(filename);
  write(fd, data, size);

  std::unique_ptr<CommandData> cmd_data(new CommandData);
  cmd_data->ParseArg(const_cast<wchar_t *>(L"-p"));
  cmd_data->ParseArg(const_cast<wchar_t *>(L"x"));
  cmd_data->ParseDone();
  std::wstring wide_filename(filename, filename + strlen(filename));
  cmd_data->AddArcName(wide_filename.c_str());

  try {
    CmdExtract extractor(cmd_data.get());
    extractor.DoExtract();
  } catch (...) {
  }

  close(fd);
  unlink(filename);

  return 0;
}
HERE

# build fuzzer
$CXX $CXXFLAGS -v -g -ggdb -std=c++11 -I. \
     $SRC/unrar/unrar_fuzzer.cc -o $OUT/unrar_fuzzer \
     -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -DRAR_SMP -DRARDLL \
     -lFuzzingEngine -L$SRC/unrar/unrar -lunrar -lstdc++
