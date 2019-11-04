#include "xerces_fuzz_common.h"

#include "xercesc/framework/MemBufInputSource.hpp"
#include "xercesc/parsers/SAXParser.hpp"
#include "xercesc/util/OutOfMemoryException.hpp"

using namespace xercesc_3_2;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    parseInMemory(Data, Size);
    return 0;
}



