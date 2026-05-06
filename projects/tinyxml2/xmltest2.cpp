/* Copyright 2024 Google LLC
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

#include "tinyxml2/tinyxml2.h"

#include <string>
#include <cstdio>
#include <cstdint>
#include <cstdlib>

#include <unistd.h>

using namespace tinyxml2;
using namespace std;

// Entry point for LibFuzzer.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	char pathname[256];
	sprintf(pathname, "/tmp/libfuzzer.%d", getpid());
	FILE *fp = fopen(pathname, "wb");
	fwrite(data, size, 1, fp);
  	fclose(fp);
    
	XMLDocument doc;
	doc.LoadFile(pathname);

    unlink(pathname);
	return 0;
}
