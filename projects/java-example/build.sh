#!/bin/bash -eu
# Copyright 2021 Google Inc.
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

# Build native library.
JVM_INCLUDES="-I$JAVA_HOME/include -I$JAVA_HOME/include/linux"
mkdir $OUT/native
$CXX $CXXFLAGS $JVM_INCLUDES -fPIC -shared \
    ExampleFuzzerNative.cpp -o $OUT/native/libnative.so

BUILD_CLASSPATH=$JAZZER_API_PATH

# All class files lie in the same directory as the fuzzer at runtime.
RUNTIME_CLASSPATH=\$this_dir

for fuzzer in $(find $SRC -name '*Fuzzer.java' -or -name '*FuzzerNative.java'); do
  fuzzer_basename=$(basename -s .java $fuzzer)
  javac -cp $BUILD_CLASSPATH $fuzzer
  cp $SRC/$fuzzer_basename.class $OUT/

  if [[ $fuzzer_basename == *FuzzerNative ]]; then
    driver=jazzer_driver_with_sanitizer
  else
    driver=jazzer_driver
  fi

  cp default.options $OUT/"$fuzzer_basename".options
  # Create execution wrapper.
  echo "#!/bin/bash
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname \"\$0\")
if [[ \"\$@\" =~ (^| )-runs=[0-9]+($| ) ]]; then
  mem_settings='-Xmx1900m:-Xss900k'
else
  mem_settings='-Xmx2048m:-Xss1024k'
fi
LD_LIBRARY_PATH=\"$JVM_LD_LIBRARY_PATH\":\$this_dir/native \
ASAN_OPTIONS=\$ASAN_OPTIONS:symbolize=1:external_symbolizer_path=\$this_dir/llvm-symbolizer:detect_leaks=0 \
\$this_dir/$driver --agent_path=\$this_dir/jazzer_agent_deploy.jar \
--cp=$RUNTIME_CLASSPATH \
--target_class=$fuzzer_basename \
--jvm_args=\"\$mem_settings\" \
\$@" > $OUT/$fuzzer_basename
  chmod +x $OUT/$fuzzer_basename
done
