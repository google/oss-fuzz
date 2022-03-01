/* Copyright 2022 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "readelf.h"

// Hack to satisfy OSS-Fuzz logic that looks for
// LLVMFuzzerTestOneInput in a binary.
char *oss_fuzz_magic_string = "LLVMFuzzerTestOneInput";

static char *my_argv[5];
int main(int argc, char **argv) {
        my_argv[0] = argv[0];
        my_argv[1] = "-a";
        my_argv[2] = argv[1];
        my_argv[3] = NULL;
        my_argv[4] = oss_fuzz_magic_string;
        return old_main(3, my_argv);
}
