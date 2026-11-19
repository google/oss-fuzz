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
//##############################################################################

#include "config.h"

#include "buffer.hpp"
#include "pci_handler.hpp"
#include "rde/external_storer_file.hpp"
#include "rde/external_storer_interface.hpp"
#include "rde/rde_handler.hpp"
#include "read_loop.hpp"

#include <sys/mman.h>
#include <unistd.h>

#include <boost/asio.hpp>
#include <boost/endian/conversion.hpp>
#include <stdplus/fd/managed.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <memory>

namespace
{
using namespace bios_bmc_smm_error_logger;

constexpr std::chrono::milliseconds readIntervalinMs(READ_INTERVAL_MS);
constexpr std::size_t memoryRegionSize = MEMORY_REGION_SIZE;
constexpr uint32_t bmcInterfaceVersion = BMC_INTERFACE_VERSION;
constexpr uint16_t queueSize = QUEUE_REGION_SIZE;
constexpr uint16_t ueRegionSize = UE_REGION_SIZE;
constexpr std::array<uint32_t, 4> magicNumber = {
    MAGIC_NUMBER_BYTE1, MAGIC_NUMBER_BYTE2, MAGIC_NUMBER_BYTE3,
    MAGIC_NUMBER_BYTE4};

constexpr uint8_t kRawHeaderSentinel = 0xA5;
constexpr uint8_t kTimerErrorSentinel = 0x5A;
constexpr std::size_t kMaxFrames = 48;
constexpr std::size_t kMaxInputSize = kMaxFrames * queueSize;

struct FuzzerState
{
    uint8_t* sharedMem = nullptr;
    std::size_t dirtyBytes = memoryRegionSize;
    std::shared_ptr<BufferInterface> bufferHandler;
    std::filesystem::path tempRootDir;

    FuzzerState()
    {
        int rawFd = memfd_create("bios_bmc_fuzz", 0);
        if (rawFd < 0 ||
            ftruncate(rawFd, static_cast<off_t>(memoryRegionSize)) != 0)
        {
            std::abort();
        }

        void* mapped = mmap(nullptr, memoryRegionSize, PROT_READ | PROT_WRITE,
                            MAP_SHARED, rawFd, 0);
        if (mapped == MAP_FAILED)
        {
            close(rawFd);
            std::abort();
        }
        sharedMem = static_cast<uint8_t*>(mapped);

        auto managedFd = std::make_unique<stdplus::ManagedFd>(std::move(rawFd));
        std::unique_ptr<DataInterface> pciDataHandler =
            std::make_unique<PciDataHandler>(0, memoryRegionSize,
                                             std::move(managedFd));
        bufferHandler = std::make_shared<BufferImpl>(std::move(pciDataHandler));

        char dirTemplate[] = "/tmp/bios_bmc_storer_XXXXXX";
        if (mkdtemp(dirTemplate) == nullptr)
        {
            std::abort();
        }
        tempRootDir = dirTemplate;
    }

    ~FuzzerState()
    {
        if (sharedMem != nullptr)
        {
            munmap(sharedMem, memoryRegionSize);
        }
        std::error_code ec;
        std::filesystem::remove_all(tempRootDir, ec);
    }
};

void normalizeHeader(CircularBufferHeader* header)
{
    for (std::size_t i = 0; i < magicNumber.size(); ++i)
    {
        header->magicNumber[i] =
            boost::endian::native_to_little(magicNumber[i]);
    }
    header->queueSize = boost::endian::native_to_little(queueSize);
    header->ueRegionSize = boost::endian::native_to_little(ueRegionSize);
    header->bmcInterfaceVersion =
        boost::endian::native_to_little(bmcInterfaceVersion);

    const std::size_t maxOffset =
        queueSize - ueRegionSize - sizeof(CircularBufferHeader);

    const uint32_t writePtr =
        boost::endian::little_to_native(header->biosWritePtr);
    header->biosWritePtr =
        boost::endian::native_to_little(writePtr % (maxOffset + 1));

    const uint32_t readPtr =
        boost::endian::little_to_native(header->bmcReadPtr);
    header->bmcReadPtr =
        boost::endian::native_to_little(readPtr % (maxOffset + 1));
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size)
{
    static FuzzerState state;

    if (size > kMaxInputSize)
    {
        size = kMaxInputSize;
    }

    boost::asio::io_context io;
    boost::asio::steady_timer t(io, readIntervalinMs);

    std::unique_ptr<rde::FileHandlerInterface> fileWriter =
        std::make_unique<rde::ExternalStorerFileWriter>(
            state.tempRootDir.native());
    std::unique_ptr<rde::ExternalStorerInterface> exFileIface =
        std::make_unique<rde::ExternalStorerFileInterface>(
            nullptr, state.tempRootDir.native(), std::move(fileWriter),
            /*numSavedLogEntries=*/1, /*numLogEntries=*/2);
    auto rdeCommandHandler =
        std::make_shared<rde::RdeCommandHandler>(std::move(exFileIface));

    std::size_t offset = 0;
    for (std::size_t frame = 0; frame < kMaxFrames; ++frame)
    {
        const std::size_t remaining = (offset < size) ? (size - offset) : 0;
        const bool isRawHeader =
            remaining >= sizeof(CircularBufferHeader) &&
            data[offset + offsetof(CircularBufferHeader, reserved2)] ==
                kRawHeaderSentinel;

        if (isRawHeader)
        {
            const std::size_t frameLen =
                std::min<std::size_t>(remaining, memoryRegionSize);
            const std::size_t clearLen =
                std::max<std::size_t>(state.dirtyBytes,
                                      std::max<std::size_t>(frameLen,
                                                            queueSize));
            std::memset(state.sharedMem, 0, clearLen);
            std::memcpy(state.sharedMem, data + offset, frameLen);
            state.dirtyBytes = std::max<std::size_t>(frameLen, queueSize);

            readLoop(&t, state.bufferHandler, rdeCommandHandler,
                     boost::system::error_code{});
            offset += frameLen;
        }
        else
        {
            const std::size_t frameLen =
                std::min<std::size_t>(remaining, queueSize);
            const std::size_t clearLen =
                std::max<std::size_t>(state.dirtyBytes, queueSize);
            std::memset(state.sharedMem, 0, clearLen);
            if (frameLen > 0)
            {
                std::memcpy(state.sharedMem, data + offset, frameLen);
            }
            state.dirtyBytes = queueSize;

            auto* header =
                reinterpret_cast<CircularBufferHeader*>(state.sharedMem);
            normalizeHeader(header);

            boost::system::error_code ec;
            if (header->reserved2 == kTimerErrorSentinel)
            {
                ec = boost::asio::error::make_error_code(
                    boost::asio::error::operation_aborted);
            }
            readLoop(&t, state.bufferHandler, rdeCommandHandler, ec);
            offset += queueSize;
        }

        if (offset >= size)
        {
            break;
        }
    }

    (void)rdeCommandHandler->getDictionaryCount();

    std::error_code fsEc;
    for (const auto& entry :
         std::filesystem::directory_iterator(state.tempRootDir, fsEc))
    {
        std::filesystem::remove_all(entry.path(), fsEc);
    }

    return 0;
}
