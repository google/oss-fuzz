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
#include <string>
#include <vector>
#include <fstream>
#include <unistd.h>
#include <cstring>
#include <algorithm>
#include <filesystem>

#include "pattern.hpp"
#include "zero.hpp"
#include "cryptErase.hpp"
#include "util.hpp"

// Implement StubCryptsetup
class StubCryptsetup : public estoraged::CryptsetupInterface {
public:
    int format_val = 0;
    int keyslot_add_val = 0;
    int load_val = 0;
    int keyslot_change_val = 0;
    int activate_val = 0;
    int deactivate_val = 0;
    int destroy_val = 0;
    int max_slots_val = 8;
    crypt_keyslot_info slot_status_val = CRYPT_SLOT_ACTIVE;

    int cryptFormat(struct crypt_device*, const char*, const char*, const char*, const char*, const char*, size_t, void*) override { return format_val; }
    int cryptKeyslotAddByVolumeKey(struct crypt_device*, int, const char*, size_t, const char*, size_t) override { return keyslot_add_val; }
    int cryptLoad(struct crypt_device*, const char*, void*) override { return load_val; }
    int cryptKeyslotChangeByPassphrase(struct crypt_device*, int, int, const char*, size_t, const char*, size_t) override { return keyslot_change_val; }
    int cryptActivateByPassphrase(struct crypt_device*, const char*, int, const char*, size_t, uint32_t) override { return activate_val; }
    int cryptDeactivate(struct crypt_device*, const char*) override { return deactivate_val; }
    int cryptKeyslotDestroy(struct crypt_device*, int keyslot) override { return destroy_val; }
    int cryptKeySlotMax(const char*) override { return max_slots_val; }
    crypt_keyslot_info cryptKeySlotStatus(struct crypt_device*, int) override { return slot_status_val; }
    std::string cryptGetDir() override { return "/tmp"; }
};

// Implement a simple Fd that reads from fuzzer input
class FuzzerFd : public stdplus::fd::Fd {
public:
    FuzzerFd(const uint8_t* data, size_t size) : data_(data), size_(size), offset_(0) {}

    std::span<const std::byte> write(std::span<const std::byte> data) override {
        return data;
    }

    std::span<std::byte> read(std::span<std::byte> buf) override {
        if (offset_ >= size_) {
            return buf.subspan(0, 0); // EOF
        }
        size_t to_read = std::min(buf.size(), size_  - offset_);
        std::memcpy(buf.data(), data_ + offset_, to_read);
        offset_ += to_read;
        return buf.subspan(0, to_read);
    }

    int ioctl(unsigned long request, void* data) override {
        if (request == BLKGETSIZE64) {
            *reinterpret_cast<uint64_t*>(data) = 1024 * 1024; // 1MB
        }
        return 0;
    }

private:
    const uint8_t* data_;
    size_t size_;
    size_t offset_;
};

// Stub the C functions that CryptHandle calls to avoid real I/O.
extern "C" {
struct crypt_device;
int crypt_init(struct crypt_device** cd, const char*) {
    *cd = reinterpret_cast<struct crypt_device*>(1); // dummy non-null
    return 0;
}
void crypt_free(struct crypt_device*) {
    // do nothing
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 1) return 0;

    uint8_t action = data[0];
    const uint8_t* fuzz_data = data + 1;
    size_t fuzz_size = size - 1;

    if (action % 4 == 0) {
        // Fuzz findPredictedMediaLifeLeftPercent
        char temp_path[] = "/tmp/estoraged_fuzz_XXXXXX";
        int fd = mkstemp(temp_path);
        if (fd == -1) return 0;
        close(fd);

        std::string dir_path = std::string(temp_path) + "_dir";
        std::filesystem::create_directory(dir_path);
        std::string file_path = dir_path + "/life_time";

        std::ofstream out(file_path, std::ios::binary);
        if (out) {
            out.write(reinterpret_cast<const char*>(fuzz_data), fuzz_size);
            out.close();
            try {
                (void)estoraged::util::findPredictedMediaLifeLeftPercent(dir_path);
            } catch (...) {}
        }

        std::filesystem::remove_all(dir_path);
        unlink(temp_path);
    }
    else if (action % 4 == 1) {
        // Fuzz Pattern
        if (fuzz_size < 8) return 0;
        uint64_t drive_size = *reinterpret_cast<const uint64_t*>(fuzz_data) % (1024 * 1024); // cap at 1MB
        fuzz_data += 8;
        fuzz_size -= 8;

        estoraged::Pattern pattern("/dev/null");
        FuzzerFd fd(fuzz_data, fuzz_size);
        try {
            pattern.writePattern(drive_size, fd);
        } catch (...) {}
        
        FuzzerFd fd2(fuzz_data, fuzz_size);
        try {
            pattern.verifyPattern(drive_size, fd2);
        } catch (...) {}
    }
    else if (action % 4 == 2) {
        // Fuzz Zero
        if (fuzz_size < 8) return 0;
        uint64_t drive_size = *reinterpret_cast<const uint64_t*>(fuzz_data) % (1024 * 1024); // cap at 1MB
        fuzz_data += 8;
        fuzz_size -= 8;

        estoraged::Zero zero("/dev/null");
        FuzzerFd fd(fuzz_data, fuzz_size);
        try {
            zero.writeZero(drive_size, fd);
        } catch (...) {}

        FuzzerFd fd2(fuzz_data, fuzz_size);
        try {
            zero.verifyZero(drive_size, fd2);
        } catch (...) {}
    }
    else if (action % 4 == 3) {
        // Fuzz CryptErase
        if (fuzz_size < 4) return 0;
        std::unique_ptr<StubCryptsetup> stub = std::make_unique<StubCryptsetup>();
        stub->load_val = fuzz_data[0] % 2 == 0 ? 0 : -1;
        stub->max_slots_val = (fuzz_data[1] % 10) - 1;
        stub->destroy_val = fuzz_data[2] % 2 == 0 ? 0 : -1;
        
        uint8_t status_byte = fuzz_data[3] % 3;
        if (status_byte == 0) stub->slot_status_val = CRYPT_SLOT_ACTIVE;
        else if (status_byte == 1) stub->slot_status_val = CRYPT_SLOT_ACTIVE_LAST;
        else stub->slot_status_val = CRYPT_SLOT_INACTIVE;

        estoraged::CryptErase cryptErase("/dev/null", std::move(stub));
        try {
            cryptErase.doErase();
        } catch (...) {}
    }

    return 0;
}
