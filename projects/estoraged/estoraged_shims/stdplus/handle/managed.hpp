#ifndef SHIM_STDPLUS_MANAGED_HPP
#define SHIM_STDPLUS_MANAGED_HPP

#include <utility>

namespace stdplus {

template <typename T>
struct Managed {
    template <void (*Deleter)(T&&)>
    class Handle {
    public:
        Handle(T&& val) : val(std::move(val)) {}
        ~Handle() { Deleter(std::move(val)); }
        T& operator*() { return val; }
        T* operator->() { return &val; }
        T& get() { return val; }
    private:
        T val;
    };
};

} // namespace stdplus

#endif // SHIM_STDPLUS_MANAGED_HPP
