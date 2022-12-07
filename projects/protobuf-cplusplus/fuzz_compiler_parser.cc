// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include "google/protobuf/compiler/parser.h"
#include "google/protobuf/io/tokenizer.h"
#include "google/protobuf/descriptor.h"
#include "google/protobuf/descriptor.pb.h"

class MockErrorCollector : public google::protobuf::io::ErrorCollector {
 public:
  MockErrorCollector() = default;
  ~MockErrorCollector() override = default;

  // implements ErrorCollector ---------------------------------------
  void AddWarning(int line, int column, const std::string& message) override {
  }

  void AddError(int line, int column, const std::string& message) override {
  }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    MockErrorCollector error_collector_;
    auto input1 = new google::protobuf::io::ArrayInputStream(data, size);
    auto input = new google::protobuf::io::Tokenizer(input1, &error_collector_);
    google::protobuf::FileDescriptorProto result;
    auto parser = new google::protobuf::compiler::Parser();

    if (parser->Parse(input, &result)) {
        auto pool = new google::protobuf::DescriptorPool();
        auto fd = pool->BuildFile(result);
        if (fd) {
            fd->DebugString();
        }
        delete pool;
    }
    delete parser;
    delete input;
    delete input1;
    return 0;
}
