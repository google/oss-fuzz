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
// The ideal place for this fuzz target is the boost repository.
#include <boost/date_time/gregorian/gregorian.hpp>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>

using namespace boost::gregorian;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    try {
        std::string s(fdp.ConsumeRandomLengthString(15));
        date d(from_simple_string(s));
        to_simple_string(d);

        date d1(from_undelimited_string(s));
        to_iso_extended_string(d1);
        
        date::ymd_type ymd = d1.year_month_day();
        greg_weekday wd = d1.day_of_week();
        wd.as_long_string();
        ymd.month.as_long_string();
    } catch(...) {
    }
    return 0;
}