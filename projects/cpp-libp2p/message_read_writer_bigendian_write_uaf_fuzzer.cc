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

#include <cstddef>
#include <cstdint>
#include <thread>
#include <vector>
#include <memory>

#include <libp2p/common/types.hpp>
#include <libp2p/outcome/outcome.hpp>
#include <libp2p/basic/readwriter.hpp>
#include <libp2p/basic/message_read_writer_bigendian.hpp>

using libp2p::BytesIn;
using libp2p::basic::MessageReadWriterBigEndian;

// Fake ReadWriter that performs asynchronous write and reads from the span
// after the initiator returns, to expose UAF if the span points to a local.
class DelayedWriter : public libp2p::basic::ReadWriter {
 public:
  void readSome(libp2p::BytesOut /*out*/, ReadCallbackFunc cb) override {
    // Not used; return error to avoid recursion
    cb(std::errc::operation_not_supported);
  }

  void deferReadCallback(outcome::result<size_t> res,
                         ReadCallbackFunc cb) override {
    cb(res);
  }

  void writeSome(BytesIn in, WriteCallbackFunc cb) override {
    // Defer the callback and touch the span after caller returns
    threads_.emplace_back([in, cb]() mutable {
      // Copy from the span (dereferences pointer that may be dangling)
      std::vector<uint8_t> copy(in.begin(), in.end());
      // Report all bytes written to terminate libp2p::write recursion
      cb(copy.size());
    });
  }

  void deferWriteCallback(std::error_code ec, WriteCallbackFunc cb) override {
    if (ec) {
      cb(ec);
    }
  }

  void joinAll() {
    for (auto &t : threads_) {
      if (t.joinable()) {
        t.join();
      }
    }
    threads_.clear();
  }

 private:
  std::vector<std::thread> threads_;
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0) {
    return 0;
  }

  auto conn = std::make_shared<DelayedWriter>();
  auto mrw = std::make_shared<MessageReadWriterBigEndian>(conn);

  BytesIn in(data, size);
  mrw->write(in, [](outcome::result<void> res) { (void)res; });

  // Ensure the deferred thread runs and touches the span
  conn->joinAll();
  return 0;
}

