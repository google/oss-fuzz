# Copyright 2022 Google LLC
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


# Ruby gems are shared objects that need to be dynamically loaded.
# OSS-Fuzz requires all the binary files to be copied to the /out
# directory, so static linking is usually recommended. Unfortunately,
# static linking prevents the dynamic loading of gems from
# working. So, instead, we need to build ruby with the
# --enabled-shared flag and copy all the relevant shared objects to
# the /out directory. We also need to invoke the fuzzer binary with
# the RUBYLIB environment variable set, so that the ruby interpreter
# is able to find those files. This script generates a C function
# named init_ruby_load_paths() which is used to set the RUBYLIB
# environment variable at runtime.

old_lib_dir = ENV["RUBY_LIB_DIR"]

n = $LOAD_PATH.length
puts "#include <stdio.h>"
puts ""
puts "static int init_ruby_load_paths(char *buf, size_t bufsize, const char *outpath) {"
puts "  return snprintf(buf, bufsize,"
i = 0
while i < n do
  path = $LOAD_PATH[i]
  if path.start_with?(old_lib_dir)
    puts "    \"%s/lib" + path.delete_prefix(old_lib_dir) + (i+1 < n ? ":\"" : "\",")
  else
    puts "#error path has incorrect prefix: " + path
  end
  i += 1
end
i = 0
while i < n do
  puts "    outpath" + (i+1 < n ? "," : "")
  i += 1
end
puts "  );"
puts "}"
