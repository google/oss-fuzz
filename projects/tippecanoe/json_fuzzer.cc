// Copyright 2021 Google LLC
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

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "jsonpull/jsonpull.h"
#include "geojson.hpp"
#include "geojson-loop.hpp"
#include "read_json.hpp"

int main2(int argc, char **argv);

extern "C"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size){
	char filename[256];
	sprintf(filename, "/tmp/libfuzzer.json");

	FILE *fp = fopen(filename, "wb");
	if (!fp)
		return 0;
	fwrite(data, size, 1, fp);
	fclose(fp);
	int argc = 2;
	char* argv[argc + 1];

	argv[0] = "tippecanoe-json-tool";
	argv[1] = filename;
	argv[2] = NULL;
	int result = main2(argc, argv);

	std::remove(filename);
	return 0;
}
