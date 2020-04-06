# Copyright 2020 Google Inc.
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
cd ./weechat
mkdir build && cd build
cmake .. -DENABLE_PHP=OFF -DENABLE_GUILE=OFF -DENABLE_TCL=OFF -DENABLE_SPELL=OFF -DENABLE_RUBY=OFF -DENABLE_PYTHON=OFF -DENABLE_LUA=OFF -DENABLE_PERL=OFF -DENABLE_ALIAS=OFF -DENABLE_XFER=OFF -DENABLE_FSET=OFF -DENABLE_LOGGER=OFF -DENABLE_RELAY=OFF -DENABLE_EXEC=OFF -DENABLE_SCRIPT=OFF -DENABLE_IRC=OFF -DENABLE_FIFO=OFF -DENABLE_BUFLIST=OFF -DENABLE_TESTS=ON -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON 

make VERBOSE=1 || true

# Now go into the build folder and construct the fuzzers
cp ../tests/fuzzers/string_fuzzer.cpp .
$CXX string_fuzzer.cpp $CXXFLAGS $LIB_FUZZING_ENGINE ./src/core/libweechat_core.a ./src/plugins/libweechat_plugins.a ./src/gui/libweechat_gui_common.a ./src/gui/curses/headless/libweechat_gui_headless.a ./src/gui/curses/headless/libweechat_ncurses_fake.a ./src/core/libweechat_core.a -lgcrypt -lgnutls -ldl -lcurl -rdynamic -I../ -o $OUT/string_fuzzer
