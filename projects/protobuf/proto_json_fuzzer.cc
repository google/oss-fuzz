#include "google/protobuf/util/json_util.h"
#include "google/protobuf/descriptor.pb.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    std::string input(reinterpret_cast<const char*>(data), size);
    google::protobuf::FileDescriptorProto proto;
    google::protobuf::util::JsonStringToMessage(input, &proto);
    return 0;
}
