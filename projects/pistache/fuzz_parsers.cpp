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
