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

#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <iostream>

#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

extern "C" int LLVMFuzzerTestOneInput(char* data, size_t size) {
  std::string str(data, size);
  std::cout << "INPUT" << str << std::endl;

  struct addrinfo *result = NULL;

  getaddrinfo(str.c_str(), NULL, NULL, &result);
  if (result) {
    freeaddrinfo(result);
  }

  return 0;
}
