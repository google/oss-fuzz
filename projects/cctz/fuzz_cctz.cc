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

#include <fuzzer/FuzzedDataProvider.h>

#include <iostream>
#include <string>

#include "cctz/civil_time.h"
#include "cctz/time_zone.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	FuzzedDataProvider fuzzed_data(data, size);

	cctz::time_zone lax;
	std::string tz = fuzzed_data.ConsumeRandomLengthString();
	if (load_time_zone(tz, &lax)) {
		std::chrono::system_clock::time_point tp;
		std::string date_format = fuzzed_data.ConsumeRandomLengthString();
		std::string parse_format = fuzzed_data.ConsumeRandomLengthString();
		cctz::parse(parse_format, date_format, lax, &tp);

		const auto t1 = cctz::convert(cctz::civil_second(
				fuzzed_data.ConsumeIntegral<uint32_t>(),
				fuzzed_data.ConsumeIntegral<uint32_t>(),
				fuzzed_data.ConsumeIntegral<uint32_t>(),
				fuzzed_data.ConsumeIntegral<uint32_t>(),
				fuzzed_data.ConsumeIntegral<uint32_t>(),
				fuzzed_data.ConsumeIntegral<uint32_t>()), lax);
		std::string format = fuzzed_data.ConsumeRandomLengthString();
		cctz::format(format, t1, lax);
	}

	return 0;
}
