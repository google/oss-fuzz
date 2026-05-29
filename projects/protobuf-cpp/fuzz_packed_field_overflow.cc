// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include <cstdint>
#include <cstring>
#include <string>

#include "google/protobuf/descriptor.h"
#include "google/protobuf/dynamic_message.h"
#include "google/protobuf/descriptor.pb.h"

static google::protobuf::DescriptorPool* pool = nullptr;
static google::protobuf::DynamicMessageFactory* factory = nullptr;
static const google::protobuf::Descriptor* msg_desc = nullptr;

static void Init() {
  google::protobuf::FileDescriptorProto file;
  file.set_name("fuzz.proto");
  file.set_syntax("proto2");

  auto* msg = file.add_message_type();
  msg->set_name("FuzzMsg");

  auto* f1 = msg->add_field();
  f1->set_name("packed_int32");
  f1->set_number(1);
  f1->set_type(google::protobuf::FieldDescriptorProto::TYPE_INT32);
  f1->set_label(google::protobuf::FieldDescriptorProto::LABEL_REPEATED);
  f1->mutable_options()->set_packed(true);

  auto* f2 = msg->add_field();
  f2->set_name("packed_fixed32");
  f2->set_number(2);
  f2->set_type(google::protobuf::FieldDescriptorProto::TYPE_FIXED32);
  f2->set_label(google::protobuf::FieldDescriptorProto::LABEL_REPEATED);
  f2->mutable_options()->set_packed(true);

  auto* f3 = msg->add_field();
  f3->set_name("packed_bool");
  f3->set_number(3);
  f3->set_type(google::protobuf::FieldDescriptorProto::TYPE_BOOL);
  f3->set_label(google::protobuf::FieldDescriptorProto::LABEL_REPEATED);
  f3->mutable_options()->set_packed(true);

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
  msg->ParseFromArray(data, static_cast<int>(size));
  delete msg;
  return 0;
}
