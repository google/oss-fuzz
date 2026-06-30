#ifndef SHIM_CONNECTION_HPP
#define SHIM_CONNECTION_HPP

#include <variant>
#include <string>

namespace sdbusplus {

struct object_path {
    std::string str;
    bool operator<(const object_path& other) const {
        return str < other.str;
    }
};

namespace asio {

class connection {};

} // namespace asio
} // namespace sdbusplus

#endif // SHIM_CONNECTION_HPP
