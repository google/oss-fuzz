#ifndef SHIM_ERROR_HPP
#define SHIM_ERROR_HPP

#include <exception>

namespace sdbusplus {
namespace xyz {
namespace openbmc_project {
namespace Common {
namespace Error {

class InternalFailure : public std::exception {
public:
    const char* what() const noexcept override { return "InternalFailure"; }
};

class ResourceNotFound : public std::exception {
public:
    const char* what() const noexcept override { return "ResourceNotFound"; }
};

} // namespace Error
} // namespace Common
} // namespace openbmc_project
} // namespace xyz
} // namespace sdbusplus

#endif // SHIM_ERROR_HPP
