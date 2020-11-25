/* Copyright 2020 Google LLC

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

#include <iostream>
#include <yaml-cpp/depthguard.h>
#include "yaml-cpp/parser.h"
#include "yaml-cpp/exceptions.h"
#include "nodebuilder.h"
#include "yaml-cpp/node/impl.h"
#include "yaml-cpp/node/node.h"

using YAML::Parser;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	std::string fuzz_input(reinterpret_cast<const char*>(data), size);
	std::istringstream input{fuzz_input};
	Parser parser{input};
	int depth=  0;
	while (true && depth < 1000) {
		depth+=1;
		YAML::NodeBuilder builder;
		try {
			if (!parser.HandleNextDocument(builder)) {
				break;
			}
		}       
		catch(YAML::ParserException) {
			break;
		}
	}
	return 0;
}
