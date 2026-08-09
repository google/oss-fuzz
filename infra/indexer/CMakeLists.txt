cmake_minimum_required(VERSION 3.19)

project(Indexer LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -stdlib=libc++ -fexperimental-library -fno-rtti")
set(CMAKE_EXE_LINKER_FLAGS "-fuse-ld=lld -lc++")

include(FetchContent)
FetchContent_Declare(
    absl
    URL https://github.com/abseil/abseil-cpp/archive/987c57f325f7fa8472fa84e1f885f7534d391b0d.zip
    # https://github.com/abseil/abseil-cpp/releases/tag/20250814.0
)
FetchContent_MakeAvailable(absl)

# Force static linking of libraries.
set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")

# LLVM / Clang
find_package(LLVM REQUIRED CONFIG COMPONENTS
    LLVMSupport
)

find_package(Clang REQUIRED CONFIG COMPONENTS
    clang-cpp
    clangTooling
    clangFrontend
    clangAST
    clangBasic
    clangLex
    clangSema
)
message(STATUS "Found LLVM: ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVM include directories: ${LLVM_INCLUDE_DIRS}")
message(STATUS "Using LLVM library directories: ${LLVM_LIBRARY_DIRS}")
include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})

# SQLite
find_package(SQLite3 REQUIRED)

# GoogleTest (for unittests)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/6910c9d9165801d8827d628cb72eb7ea9dd538c5.zip
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_library(index
    index/file_copier.cc
    index/in_memory_index.cc
    index/sqlite.cc
    index/types.cc
    index/in_memory_index.h
    index/sqlite.h
    index/types.h
)
target_include_directories(index PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/..
)
target_link_libraries(index PUBLIC
    absl::flat_hash_map
    absl::log
    absl::check
    absl::strings
    absl::span
    SQLite::SQLite3
)

add_library(merge_queue
    merge_queue.cc
    queue_state.cc
    merge_queue.h
    queue_state.h
)
target_link_libraries(merge_queue PUBLIC
    absl::base
    absl::log
    absl::strings
    absl::synchronization
    index
)
target_include_directories(merge_queue PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/..
)
add_library(frontend
    frontend/ast_visitor.cc
    frontend/common.cc
    frontend/frontend.cc
    frontend/index_action.cc
    frontend/pp_callbacks.cc
    frontend/ast_visitor.h
    frontend/common.h
    frontend/frontend.h
    frontend/index_action.h
    frontend/pp_callbacks.h
)
target_include_directories(frontend PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/..
)
target_link_libraries(frontend PUBLIC
    absl::flags
    absl::log
    absl::check
    absl::strings
    LLVMSupport
    clangAST
    clangBasic
    clangFrontend
    clangLex
    clangSema
    clangTooling
    index
    merge_queue
)
target_include_directories(frontend INTERFACE SYSTEM ${LLVM_INCLUDE_DIRS})

add_executable(indexer main.cc)
target_link_libraries(indexer PRIVATE
    absl::flags
    absl::flags_parse
    absl::log
    absl::log_initialize
    absl::check
    absl::string_view
    LLVMSupport
    clangTooling
    frontend
    index
    merge_queue
    -static
)

enable_testing()
include(GoogleTest)

add_executable(index_unittest
    index/file_copier_unittest.cc
    index/in_memory_index_unittest.cc
    index/types_unittest.cc
)
target_link_libraries(index_unittest PRIVATE
    GTest::gmock_main
    absl::hash
    absl::strings
    index
)
gtest_discover_tests(index_unittest)

add_executable(frontend_test
    frontend/frontend_test.cc
)
target_link_libraries(frontend_test PRIVATE
    frontend
    index
    GTest::gmock_main
)
gtest_discover_tests(frontend_test)
