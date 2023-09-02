/* Copyright 2021 Google LLC
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
#include <folly/json.h>
#include <folly/experimental/JSONSchema.h>

#include <folly/experimental/symbolizer/Elf.h>
#include <folly/IPAddress.h>

#include <folly/FileUtil.h>
#include <folly/experimental/TestUtil.h>
#include <folly/experimental/symbolizer/detail/Debug.h>


// We have a better version than the one above
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        std::string input(reinterpret_cast<const char*>(data), size);

	try {
	  folly::IPAddress v4addr(input.c_str());
	} catch (...) {}

	try{
	  folly::IPAddress v6map(input.c_str());
	} catch(...){}

	try {
	  folly::IPAddress::tryCreateNetwork(input.c_str());
	} catch(...) {}


	return 0;
}

