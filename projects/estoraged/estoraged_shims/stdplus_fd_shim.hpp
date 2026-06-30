#ifndef SHIM_STDPLUS_FD_HPP
#define SHIM_STDPLUS_FD_HPP

#include <span>
#include <cstddef>
#include <string>
#include <cstdint>
#include <linux/fs.h>
#include <stdexcept>

// Reopen boost::container to add the missing alias if needed
namespace boost {
namespace container {
using out_of_range = std::out_of_range;
}
}

namespace stdplus {
namespace fd {

enum class OpenAccess {
    ReadOnly,
    WriteOnly,
    ReadWrite
};

struct OpenFlags {
    OpenAccess access;
    OpenFlags(OpenAccess a) : access(a) {}
};

class Fd {
public:
    virtual ~Fd() = default;
    virtual std::span<const std::byte> write(std::span<const std::byte> data) = 0;
    virtual std::span<std::byte> read(std::span<std::byte> buf) = 0;
    virtual int ioctl(unsigned long request, void* data) = 0;
};

class ManagedFd : public Fd {
public:
    ManagedFd() = default;
    ManagedFd(ManagedFd&&) = default;
    ManagedFd& operator=(ManagedFd&&) = default;

    std::span<const std::byte> write(std::span<const std::byte> data) override { return data; }
    std::span<std::byte> read(std::span<std::byte> buf) override { 
        return buf; 
    }
    int ioctl(unsigned long request, void* data) override {
        if (request == BLKGETSIZE64) {
            *reinterpret_cast<uint64_t*>(data) = 1024 * 1024; // 1MB dummy size
        }
        return 0;
    }
    int get() const { return 0; }
};

inline ManagedFd open(const std::string&, OpenAccess) {
    return ManagedFd();
}
inline ManagedFd open(const std::string&, OpenFlags) {
    return ManagedFd();
}
inline ManagedFd open(const char*, OpenFlags) {
    return ManagedFd();
}

} // namespace fd
} // namespace stdplus
#endif
