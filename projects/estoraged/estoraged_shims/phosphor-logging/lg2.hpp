#ifndef SHIM_LG2_HPP
#define SHIM_LG2_HPP

namespace lg2 {

template<typename... Args>
inline void error(const char*, Args&&...) {}

template<typename... Args>
inline void info(const char*, Args&&...) {}

} // namespace lg2

#endif // SHIM_LG2_HPP
