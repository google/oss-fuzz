#pragma once

namespace lg2 {
    template <typename... Args>
    void error(const char* msg, Args&&... args) {}
    
    // We might also need info, debug, warning if they are used in other files
    template <typename... Args>
    void info(const char* msg, Args&&... args) {}
    template <typename... Args>
    void warning(const char* msg, Args&&... args) {}
    template <typename... Args>
    void debug(const char* msg, Args&&... args) {}
}

#define PHOSPHOR_LOG2_USING using namespace lg2
