// Copyright 2026 Google LLC
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
#include <cstddef>
#include <vector>
#include <string>
#include <cstring>
#include <algorithm>
#include <span>
#include <memory>
#include <chrono>

#include <fuzzer/FuzzedDataProvider.h>

#include "payload_update.hpp"
#include "sys.hpp"
#include "host_command.hpp"
#include "google3/host_commands.h"

// Mock the Sys interface to read from fuzzer data in memory
class FuzzerSys : public google::hoth::internal::Sys {
public:
    FuzzerSys(const uint8_t* data, size_t size) : data_(data), size_(size), offset_(0) {}

    int open(const char* pathname, int flags) const override {
        return 42; // dummy fd
    }

    int close(int fd) const override {
        return 0;
    }

    off_t lseek(int fd, off_t offset, int whence) const override {
        if (whence == SEEK_SET) {
            if (offset < 0 || static_cast<size_t>(offset) > size_) return -1;
            offset_ = offset;
        } else if (whence == SEEK_END) {
            offset_ = size_;
        } else if (whence == SEEK_CUR) {
            if (static_cast<ssize_t>(offset_) + offset < 0 || static_cast<size_t>(offset_ + offset) > size_) return -1;
            offset_ += offset;
        }
        return offset_;
    }

    ssize_t read(int fd, void* buf, size_t count) const override {
        if (offset_ >= size_) return 0;
        size_t to_read = std::min(count, size_ - offset_);
        std::memcpy(buf, data_ + offset_, to_read);
        offset_ += to_read;
        return to_read;
    }

    ssize_t write(int fd, const void* buf, size_t count) const override {
        return count; // dummy write
    }

    int ioctl(int fd, uint64_t request, void* mtd) const override {
        return 0;
    }

private:
    const uint8_t* data_;
    size_t size_;
    mutable size_t offset_;
};

// Mock the HostCommand interface to avoid real Hoth communication
class FuzzerHostCommand : public google::hoth::internal::HostCommand {
public:
    std::vector<uint8_t> sendCommand(const std::vector<uint8_t>& command) override {
        return {};
    }
    std::vector<uint8_t> sendCommand(const std::vector<uint8_t>& command, std::chrono::milliseconds timeout) override {
        return {};
    }
    std::vector<uint8_t> sendCommand(uint16_t command, uint8_t commandVersion, const void* request, size_t requestSize) override {
        // Return a dummy response with EC_RES_SUCCESS
        std::vector<uint8_t> rsp(sizeof(google::hoth::internal::RspHeader), 0);
        auto* hdr = reinterpret_cast<google::hoth::internal::RspHeader*>(rsp.data());
        hdr->result = google::hoth::internal::EC_RES_SUCCESS;
        return rsp;
    }
    std::vector<uint8_t> sendCommand(uint16_t command, uint8_t commandVersion, const void* request, size_t requestSize, std::chrono::milliseconds timeout) override {
        return sendCommand(command, commandVersion, request, requestSize);
    }
    uint64_t sendCommandAsync(const std::vector<uint8_t>& command) override {
        return 0;
    }
    std::vector<uint8_t> getResponse(uint64_t callToken) override {
        return {};
    }
    bool communicationFailure() const override {
        return false;
    }
    int collectHothLogsAsync(bool cleanupPromiseAfterExecution) override {
        return 0;
    }
    void collectUartLogsAsync() override {}
    void stopUartLogs() override {}
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 2) return 0;

    FuzzedDataProvider provider(data, size);

    // Allocate up to 80% of fuzzer data to represent the firmware file contents
    size_t file_data_len = provider.ConsumeIntegralInRange<size_t>(0, provider.remaining_bytes() * 8 / 10);
    std::vector<uint8_t> file_data = provider.ConsumeBytes<uint8_t>(file_data_len);

    FuzzerSys fuzzer_sys(file_data.data(), file_data.size());
    FuzzerHostCommand fuzzer_host_cmd;
    google::hoth::internal::PayloadUpdateImpl payload_update(&fuzzer_host_cmd, &fuzzer_sys);

    size_t action_count = 0;
    while (provider.remaining_bytes() > 0 && action_count < 20) {
        action_count++;
        uint8_t action = provider.ConsumeIntegralInRange<uint8_t>(0, 8);
        try {
            switch (action) {
                case 0: {
                    payload_update.initiate();
                    break;
                }
                case 1: {
                    uint32_t offset = provider.ConsumeIntegral<uint32_t>();
                    uint32_t size = provider.ConsumeIntegral<uint32_t>();
                    payload_update.erase(offset, size);
                    break;
                }
                case 2: {
                    payload_update.eraseAndSendStaticWP("/tmp/fuzz_file");
                    break;
                }
                case 3: {
                    uint32_t offset = provider.ConsumeIntegral<uint32_t>();
                    uint32_t read_len = provider.ConsumeIntegralInRange<uint32_t>(0, 1024);
                    std::vector<uint8_t> read_buf(read_len);
                    payload_update.read(offset, read_buf);
                    break;
                }
                case 4: {
                    payload_update.verify();
                    break;
                }
                case 5: {
                    payload_update.getStatus();
                    break;
                }
                case 6: {
                    auto side = provider.PickValueInArray({google::hoth::internal::Side::A, google::hoth::internal::Side::B});
                    auto persistence = provider.PickValueInArray({google::hoth::internal::Persistence::kNonPersistent, google::hoth::internal::Persistence::kPersistent});
                    payload_update.activate(side, persistence);
                    break;
                }
                case 7: {
                    payload_update.send("/tmp/fuzz_file");
                    break;
                }
                case 8: {
                    auto option = provider.PickValueInArray({
                        payload_update_confirm_option::Enable,
                        payload_update_confirm_option::Enable_with_timeout,
                        payload_update_confirm_option::Disable,
                        payload_update_confirm_option::Confirm,
                        payload_update_confirm_option::Get_timeout_values
                    });
                    uint32_t timeout = provider.ConsumeIntegral<uint32_t>();
                    uint64_t cookie = provider.ConsumeIntegral<uint64_t>();
                    payload_update.confirm(option, timeout, cookie);
                    break;
                }
            }
        } catch (...) {
            // Catch expected exceptions (e.g. from mock filesystem or D-Bus response failures)
        }
    }

    return 0;
}
