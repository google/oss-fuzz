#include "store-api.hh"


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {

    using namespace nix;

    // Early assertion checks for absolute path; Don't let it fail.
    if (Data[0] != '/')
        return 0;

    auto store = openStore("dummy://");
    std::string path = std::string((char*)Data, Size);

    try {
        store->Store::parseStorePath(path);
    }
    // Some errors are legitimate, so we want to gracefully return when they are raised.
    catch(const BadStorePath &) {
        return 0;
    }

    return 0;
}
