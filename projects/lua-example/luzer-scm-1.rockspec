package = "luzer"
version = "scm-1"
source = {
    url = "git+https://github.com/ligurio/luzer",
    branch = "ligurio/oss-fuzz",
}

description = {
    summary = "A coverage-guided, native Lua fuzzer",
    detailed = [[ luzer is a coverage-guided Lua fuzzing engine. It supports
fuzzing of Lua code, but also C extensions written for Lua. Luzer is based off
of libFuzzer. When fuzzing native code, luzer can be used in combination with
Address Sanitizer or Undefined Behavior Sanitizer to catch extra bugs. ]],
    homepage = "https://github.com/ligurio/luzer",
    maintainer = "Sergey Bronnikov <estetus@gmail.com>",
    license = "ISC",
}

dependencies = {
    "lua >= 5.1",
}

build = {
    type = "cmake",
    -- luacheck: push no max_comment_line_length
    -- https://github.com/luarocks/luarocks/blob/7ed653f010671b3a7245be9adcc70068c049ef68/docs/config_file_format.md#config-file-format
    -- luacheck: pop
    variables = {
        CMAKE_LUADIR = "$(LUADIR)",
        CMAKE_LIBDIR = "$(LIBDIR)",
        CMAKE_BUILD_TYPE = "RelWithDebInfo",
        CMAKE_C_COMPILER = "clang-18",
        CMAKE_CXX_COMPILER = "clang++-18",
    },
}
