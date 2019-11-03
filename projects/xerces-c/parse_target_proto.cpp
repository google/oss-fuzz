#include "xercesc/parsers/SAXParser.hpp"
#include "xercesc/framework/MemBufInputSource.hpp"
#include "xercesc/util/OutOfMemoryException.hpp"
#include "xerces_fuzz_common.cpp"
#include "genfiles/xml.pb.h"
#include "xmlProtoConverter.h"
#include "src/libfuzzer/libfuzzer_macro.h"
#include <iostream>

namespace {
    protobuf_mutator::protobuf::LogSilencer log_silincer;
    void ignore(void* ctx, const char* msg, ...) {}

    template <class T, class D>
    std::unique_ptr<T, D> MakeUnique(T* obj, D del) {
    return {obj, del};
    }
}

//https://github.com/google/libprotobuf-mutator/tree/master/examples/libxml2
using namespace xercesc_3_2;

DEFINE_PROTO_FUZZER(const xmlProtoFuzzer::XmlDocument& xmlDocument) {
    std::string xmlData = xmlProtoFuzzer::ProtoConverter().protoToString(xmlDocument);
    parseInMemory((const uint8_t *)xmlData.c_str(), xmlData.size());
}



