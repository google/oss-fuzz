#include "xercesc/parsers/SAXParser.hpp"
#include "xercesc/framework/MemBufInputSource.hpp"
#include "xercesc/util/OutOfMemoryException.hpp"
#include "xerces_fuzz_common.cpp"
//https://github.com/google/libprotobuf-mutator/tree/master/examples/libxml2
using namespace xercesc_3_2;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    return parseInMemory(Data, Size);
}



