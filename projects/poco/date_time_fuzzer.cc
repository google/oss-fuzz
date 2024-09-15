// Copyright 2024 Google LLC
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

#include "Poco/DateTimeParser.h"
#include "Poco/DateTimeFormat.h"
#include "Poco/DateTimeFormatter.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const std::string input(reinterpret_cast<const char *>(data), size);

  const std::string formats[] = {
    Poco::DateTimeFormat::ISO8601_FORMAT,
    Poco::DateTimeFormat::ISO8601_FRAC_FORMAT,
    Poco::DateTimeFormat::RFC822_FORMAT,
    Poco::DateTimeFormat::RFC1123_FORMAT,
    Poco::DateTimeFormat::HTTP_FORMAT,
    Poco::DateTimeFormat::RFC850_FORMAT,
    Poco::DateTimeFormat::RFC1036_FORMAT,
    Poco::DateTimeFormat::ASCTIME_FORMAT,
    Poco::DateTimeFormat::SORTABLE_FORMAT,
    "%m/%d/%y %h:%M %a",
    "T%H:%M:%F",
  };

  int tzd = 0;
  Poco::DateTime dt;

  for (const auto& format : formats) {
    Poco::DateTimeParser::tryParse(format, input, dt, tzd);
    Poco::DateTimeFormatter::format(dt.timestamp(), format, tzd);
  }

  dt.makeLocal(tzd);
  dt.makeUTC(tzd);

  try {
    dt = Poco::DateTimeParser::parse(input, tzd);
  } catch (const std::exception &) {
  }

  return 0;
}
