#include <cstdlib>
#include <string>
#include "ini.h"

int dumper(void* user, const char* section, const char* name,
           const char* value)
{
    return 1;
}

void parse(const char* string) 
{
    int u = 100;
    int e = ini_parse_string(string, dumper, &u);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    std::string str(reinterpret_cast<const char*>(data), size);
    parse(str.c_str());
    return 0;
}
