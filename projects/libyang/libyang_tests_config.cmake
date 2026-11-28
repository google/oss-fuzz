# Generate tests/tests_config.h the same way tests/CMakeLists.txt does.
# A static OSS-Fuzz build sets ENABLE_TESTS=OFF, so that subdirectory is never
# configured and the header is otherwise missing for the fuzz harnesses.
if(NOT PROJECT_SOURCE_DIR OR NOT PROJECT_BINARY_DIR)
    message(FATAL_ERROR "PROJECT_SOURCE_DIR and PROJECT_BINARY_DIR must be set")
endif()

set(CMAKE_CURRENT_SOURCE_DIR "${PROJECT_SOURCE_DIR}/tests")
set(CMAKE_CURRENT_BINARY_DIR "${PROJECT_BINARY_DIR}/tests")

configure_file(
    "${PROJECT_SOURCE_DIR}/tests/tests_config.h.in"
    "${PROJECT_BINARY_DIR}/tests/tests_config.h"
    ESCAPE_QUOTES @ONLY)
