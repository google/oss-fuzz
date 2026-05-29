// Copyright 2026 Google LLC
//
// Fuzz target for signed integer overflow in ReadPackedFixed /
// ReadPackedVarintArrayWithField (CVE candidate — parse_context.h).
//
// Triggers the overflow by feeding a crafted packed repeated field
// to Message::ParseFromArray via a message that contains a packed int32 field.

#include <cstdint>
#include <cstring>
#include <string>

#include "google/protobuf/descriptor.h"
#include "google/protobuf/dynamic_message.h"
#include "google/protobuf/descriptor.pb.h"

// We use a FileDescriptorProto to dynamically define a message with a
// packed repeated int32 field, then parse fuzzer input as that message.
// This exercises ReadPackedFixed / ReadPackedVarintArrayWithField directly.

static google::protobuf::DescriptorPool* pool = nullptr;
static google::protobuf::DynamicMessageFactory* factory = nullptr;
static const google::protobuf::Descriptor* msg_desc = nullptr;

static void Init() {
  google::protobuf::FileDescriptorProto file;
  file.set_name("fuzz.proto");
  file.set_syntax("proto2");

  auto* msg = file.add_message_type();
  msg->set_name("FuzzMsg");

  // packed repeated int32 — exercises ReadPackedVarintArrayWithField
  auto* f1 = msg->add_field();
  f1->set_name("packed_int32");
  f1->set_number(1);
  f1->set_type(google::protobuf::FieldDescriptorProto::TYPE_INT32);
  f1->set_label(google::protobuf::FieldDescriptorProto::LABEL_REPEATED);
  f1->set_options_json_name("packed_int32");
  auto* opts = f1->mutable_options();
  opts->set_packed(true);

  // packed repeated fixed32 — exercises ReadPackedFixed<uint32_t>
  auto* f2 = msg->add_field();
  f2->set_name("packed_fixed32");
  f2->set_number(2);
  f2->set_type(google::protobuf::FieldDescriptorProto::TYPE_FIXED32);
  f2->set_label(google::protobuf::FieldDescriptorProto::LABEL_REPEATED);
  auto* opts2 = f2->mutable_options();
  opts2->set_packed(true);

  // packed repeated bool — exercises ReadPackedVarintArrayWithField<bool>
  auto* f3 = msg->add_field();
  f3->set_name("packed_bool");
  f3->set_number(3);
  f3->set_type(google::protobuf::FieldDescriptorProto::TYPE_BOOL);
  f3->set_label(google::protobuf::FieldDescriptorProto::LABEL_REPEATED);
  auto* opts3 = f3->mutable_options();
  opts3->set_packed(true);

  pool = new google::protobuf::DescriptorPool();
  pool->BuildFile(file);
  msg_desc = pool->FindMessageTypeByName("FuzzMsg");
  factory = new google::protobuf::DynamicMessageFactory(pool);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static bool initialized = false;
  if (!initialized) {
    Init();
    initialized = true;
  }

  if (msg_desc == nullptr) return 0;

  const google::protobuf::Message* prototype = factory->GetPrototype(msg_desc);
  if (!prototype) return 0;

  google::protobuf::Message* msg = prototype->New();
  // ParseFromArray calls EpsCopyInputStream which routes through
  // ReadPackedFixed / ReadPackedVarintArrayWithField — the vulnerable paths.
  msg->ParseFromArray(data, static_cast<int>(size));
  delete msg;

  return 0;
}
