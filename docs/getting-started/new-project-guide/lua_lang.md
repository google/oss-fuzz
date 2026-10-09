---
layout: default
title: Integrating a Lua project
parent: Setting up a new project
grand_parent: Getting started
nav_order: 4
permalink: /getting-started/new-project-guide/lua-lang/
---

# Integrating a Lua project
{: .no_toc}

- TOC
{:toc}
---

The process of integrating a project written in Lua with OSS-Fuzz
is similar to the general [Setting up a new project]({{ site.baseurl
}}/getting-started/new-project-guide/) process. The key specifics of
integrating a Lua project are outlined below.

## luzer

Lua fuzzing in OSS-Fuzz is powered by
[luzer](https://github.com/ligurio/luzer). As luzer operates
directly on the Lua source code level, it can be applied to any
project written in a language that can be transpiled into Lua,
such as [MoonScript](https://moonscript.org/),
[TypeScriptToLua](https://typescripttolua.github.io/),
[Fennel](https://fennel-lang.org/), and [Urn](https://urn-lang.com/).
Also, it supports fuzzing C/C++ extensions written for Lua. When
fuzzing native code, luzer can be used in combination with
Address Sanitizer or Undefined Behavior Sanitizer to catch extra bugs.

## Project files

### Example project

We recommend viewing
[lua-example](https://github.com/google/oss-fuzz/tree/master/projects/lua-example)
as an example of a simple Lua fuzzing project. This example also
demonstrates how to use luzer's Fuzzed Data Provider.

### project.yaml

The `language` attribute must be specified as follows:

```yaml
language: c
```

The only supported fuzzing engine is libFuzzer (`libfuzzer`).

```yaml
fuzzing_engines:
  - libfuzzer
sanitizers:
  - none
```

There is nothing special for sanitizer support in OSS-Fuzz
infrastructure. luzer builds its own DSO with libFuzzer and
sanitizer and `compile_lua_fuzzer` (also managed by project) sets
it to `LD_PRELOAD` if required.

### Dockerfile

The Dockerfile should start by `FROM gcr.io/oss-fuzz-base/base-builder`.

The OSS-Fuzz base Docker images come without any pre-installed
components required for Lua fuzzing. Apart from that, you should
usually need to build or install a Lua runtime, luzer module,
clone the project, set a `WORKDIR`, and copy any necessary files,
or install any project-specific dependencies here as you normally would.

### Fuzzers

In the simplest case, every fuzzer consists of a single Lua file that defines
a function `TestOneInput` and executes a function named `luzer.Fuzz()`.
An example fuzz target could thus be a file `fuzz_basic.lua` with contents:

```lua
local parser = require("src.luacheck.parser")
local decoder = require("luacheck.decoder")
local luzer = require("luzer")

local function TestOneInput(buf)
    parser.parse(decoder.decode(buf))
end

local args = {
    print_final_stats = 1,
}
luzer.Fuzz(TestOneInput, nil, args)
```

### compile_lua_fuzzer

Unlike projects for other languages, the base image does not
include a script that generates a wrapper script that can be used
as a drop-in replacement for libFuzzer.

Therefore, you need to add such a script yourself. This script
sets a relative path to Lua runtime that will be used for running
tests and the necessary environment variables (for example, `LUA_PATH`,
`LUA_CPATH` and `LD_PRELOAD`) and specifies the path directly to
the `.lua` file containing the test implementation. The script
`compile_lua_fuzzer` must accept the same command line flags as
libFuzzer-based tests.

Note, the resulting wrapper scripts must contain the word "luarocks"
to pass checks by `bad_build_check` in continuous integration.

Then, you can use the script `compile_lua_fuzzer` to build the fuzzers.
A usage example from the `lua-example` project is

```shell
compile_lua_fuzzer lua fuzz_basic.lua
```

Arguments are:

* a relative path to a Lua runtime name
* a relative path to the fuzzing test inside the OSS Fuzz project directory

The `lua-example` projects includes an
[example](https://github.com/google/oss-fuzz/blob/master/projects/lua-example/compile_lua_fuzzer)
of such script.

### build.sh

The script is executed within the image built from your [Dockerfile](#Dockerfile).

In general, this script should do the following:

- Set up or build a Lua runtime.
- Set up or build required dependencies for your tests.
- Generate wrapper scripts for your tests using [compile_lua_fuzzer](#compile_lua_fuzzer).

Resulting binaries, tests and their wrapper scripts, and a
directory with Luarocks dependencies should be placed in `$OUT`.

Beware, when installing the luzer module, you need to set the
environment variable `OSS_FUZZ` to non-empty value, otherwise the
build may fail.

The [lua-example](https://github.com/google/oss-fuzz/blob/master/projects/lua-example/build.sh)
project contains an example of a `build.sh` for a Lua projects.

## FuzzedDataProvider

luzer provides a Fuzzed Data Provider that is helpful for splitting
a fuzz input into multiple parts of various Lua types. Its
functionality is similar to
[Fuzzed Data Provider](https://github.com/google/fuzzing/blob/master/docs/split-inputs.md#fuzzed-data-provider)
available in LLVM. Learn about methods, provided by FDP in luzer,
in [documentation](https://github.com/ligurio/luzer/blob/master/docs/api.md#structure-aware-fuzzing).

A fuzz target using the `FuzzedDataProvider` would look as follows:

```lua
local luzer = require("luzer")

local function TestOneInput(buf)
    local fdp = luzer.FuzzedDataProvider(buf)
    local str = fdp:consume_string(4)

    local b = {}
    str:gsub(".", function(c) table.insert(b, c) end)
    local count = 0
    if b[1] == "o" then count = count + 1 end
    if b[2] == "o" then count = count + 1 end
    if b[3] == "p" then count = count + 1 end
    if b[4] == "s" then count = count + 1 end

    if count == 4 then assert(nil) end
end

local args = {
    only_ascii = 1,
    print_pcs = 1,
}

luzer.Fuzz(TestOneInput, nil, args)
```
