// Copyright 2016 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <fstream>

#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  std::string out_path, conf_path, cmd;
  std::ofstream fc;
  int wstatus;
  const char *env[] = {"ASAN_OPTIONS=detect_leaks=0", NULL};

  out_path = getenv("OUT");
  conf_path = out_path + "/conf/nginx.conf";

  fc.open(conf_path, std::ios::out | std::ios::binary);
  fc.write((char*) data, size);
  fc.close();

  pid_t pid = fork();

  if (pid == 0) {
    cmd = out_path + "/sbin/nginx";
    execle(cmd.c_str(), "nginx", "-c", conf_path.c_str(), NULL, env);
  }

  if (pid < 0) {
      return 1;
  }

  waitpid(pid, &wstatus, 0);

  return 0;
}
