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
#include <span>
#include <memory>

#include <libp2p/common/types.hpp>
#include <libp2p/outcome/outcome.hpp>
#include <libp2p/basic/readwriter.hpp>
#include <libp2p/basic/message_read_writer_bigendian.hpp>

using libp2p::BytesIn;
using libp2p::BytesOut;
using libp2p::basic::MessageReadWriterBigEndian;

class PrefixReader : public libp2p::basic::ReadWriter {
 public:
  PrefixReader(const uint8_t *data, size_t size) : data_(data), size_(size) {}

  void readSome(BytesOut out, ReadCallbackFunc cb) override {
    if (phase_ == 0) {
      // Supply exactly kLenMarkerSize bytes (or zeros if insufficient input)
      for (size_t i = 0; i < out.size(); ++i) {
        uint8_t b = 0;
        if (pos_ < size_) {
          b = data_[pos_++];
        }
        out[i] = b;
      }
      phase_ = 1;
      cb(out.size());
    } else {
      // Return error on subsequent reads to avoid full payload
      cb(std::errc::message_size);
    }
  }

  void deferReadCallback(outcome::result<size_t> res,
                         ReadCallbackFunc cb) override {
    cb(res);
  }

  void writeSome(BytesIn in, WriteCallbackFunc cb) override {
    // Not used; pretend success
    cb(in.size());
  }

  void deferWriteCallback(std::error_code ec, WriteCallbackFunc cb) override {
    if (ec) {
      cb(ec);
    }
  }

 private:
  const uint8_t *data_;
  size_t size_;
  size_t pos_ = 0;
  int phase_ = 0;
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  auto conn = std::make_shared<PrefixReader>(data, size);
  auto mrw = std::make_shared<MessageReadWriterBigEndian>(conn);

  mrw->read([](libp2p::basic::MessageReadWriter::ReadCallback) {
    // ignore result
  });
  return 0;
}

