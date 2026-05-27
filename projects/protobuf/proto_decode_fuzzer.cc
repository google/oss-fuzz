#include <stddef.h>
#include <stdint.h>
#include "google/protobuf/message.h"
#include "google/protobuf/descriptor.pb.h"

// Fuzz ParseFromString on a FileDescriptorProto (self-describing protobuf)
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    google::protobuf::FileDescriptorProto proto;
    std::string input(reinterpret_cast<const char*>(data), size);
    proto.ParseFromString(input);
    // Also test SerializeToString roundtrip
    std::string output;
    proto.SerializeToString(&output);
    google::protobuf::FileDescriptorProto proto2;
    proto2.ParseFromString(output);
    return 0;
}
