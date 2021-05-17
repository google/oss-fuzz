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
#include <pistache/http.h>

using namespace Pistache;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    std::string input(reinterpret_cast<const char*>(data), size);

    // URI parsing
    Http::Uri::Query query1;
    query1.add(input, input);

    // HTTP parsing
    Pistache::Http::Header::CacheControl cc1;
    try {
        cc1.parse(input);
    } catch(...) {}

    Pistache::Http::Header::Accept a1;
    try {
        a1.parse(input);
    } catch(...) {}

    Pistache::Http::Header::Accept a2;
    try {
        a2.parse(input);
    } catch (...) {}

    Pistache::Http::Header::Authorization au;
    try {
        au.parse(input);
    } catch(...) {}

    Pistache::Http::Header::Expect e;
    try {
        e.parse(input);
    } catch(...) {}

    Pistache::Http::Header::Connection connection;
    try {
        connection.parse(input);
    } catch(...) {}

    Pistache::Http::Header::Date d;
    try {
        d.parse(input);
    } catch(...) {}

    Pistache::Http::Header::Host h;
    try {
        h.parse(input);
    } catch(...) {}

    Pistache::Http::Header::ContentEncoding ce;
    try {
        ce.parse(input);
    } catch(...) {}

    Pistache::Http::Header::ContentType ct;
    try {
        ct.parse(input);
    } catch(...) {}

    return 0;
}
