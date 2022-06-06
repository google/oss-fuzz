/*
 * Copyright 2022 Google LLC

 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at

 *      http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/
/* A wrapper of libnmap_target.py, the target program under test,
 * inputs will be injected into its shell command as parameters. */

#include <stdlib.h>

#include <iostream>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(char* data, size_t size) {
  std::string str(data, size);
  system(("python3 ./libnmap_target.py " + str).c_str());
  return 0;
}
