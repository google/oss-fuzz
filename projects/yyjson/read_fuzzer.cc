/*
# Copyright 2021 Google LLC
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
*/

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "yyjson.h"

extern "C"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size){
	char *json = (char *)malloc(size+1);
	if (json == NULL){
		return 0;
	}
	memcpy(json, data, size);
	json[size] = '\0';
	
	yyjson_doc *doc = yyjson_read(json, strlen(json), 0);
	
	free(json);
	return 0;
}
