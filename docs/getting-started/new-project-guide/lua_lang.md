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

The process of integrating a project written in Lua with OSS-Fuzz is very
similar to the general [Setting up a new project]({{ site.baseurl
}}/getting-started/new-project-guide/) process. The key specifics of
integrating a Lua project are outlined below.

## luzer

Lua fuzzing in OSS-Fuzz is powered by
[luzer](https://github.com/ligurio/luzer), which is installed during the build
step. As luzer operates directly on the Lua source code level, it can be
applied to any project written in a language that can be transpiled into Lua
such as [MoonScript](https://moonscript.org/),
[TypeScriptToLua](https://typescripttolua.github.io/),
[Fennel](https://fennel-lang.org/), and [Urn](https://urn-lang.com/). More
information on how luzer fuzz targets looks like can be found in its [README's
Quickstart section](https://github.com/ligurio/luzer#quickstart).

## Project files

### Example project

We recommend viewing
[lua-example](https://github.com/google/oss-fuzz/tree/master/projects/lua-example)
as an example of a simple Lua fuzzing project. This example also demonstrates
how to use luzer's fuzzed data provider.

### project.yaml

The `language` attribute must be specified as follows:

```yaml
language: lua
```

The only supported fuzzing engine is libFuzzer (`libfuzzer`). The supported
sanitizers are AddressSanitizer (`address`) and
UndefinedBehaviorSanitizer (`undefined`). These must be explicitly specified.
(`none`) is the default sanitizer for Lua projects, so setting it up in
`project.yaml` is optional.

```yaml
fuzzing_engines:
  - libfuzzer
sanitizers:
  - none
```

### Dockerfile

The Dockerfile should start by `FROM gcr.io/oss-fuzz-base/base-builder`.

The OSS-Fuzz base Docker images come without any pre-installed components
required for Lua fuzzing. Apart from that, you should usually need to install
Lua runtime, luzer module, clone the project, set a `WORKDIR`, and copy any
necessary files, or install any project-specific dependencies here as you normally would.

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

### build.sh

The OSS-Fuzz base docker image for Lua comes with the [`compile_lua_fuzzer`
script](https://github.com/google/oss-fuzz/blob/master/infra/base-images/base-builder/compile_lua_fuzzer)
preinstalled. In `build.sh`, you should install dependencies for your project,
and if necessary compile the code into Lua. Then, you can use the script to
build the fuzzers. The script ensures that
[luzer](https://luarocks.org/modules/ligurio/luzer) is installed so that its
CLI can be used to execute your fuzz tests. It also generates a wrapper script
that can be used as a drop-in replacement for libFuzzer. This means that the
generated script accepts the same command line flags for libFuzzer. Under the
hood these flags are simply forwarded to the libFuzzer native addon used by
luzer.

A usage example from the lua-example project is

```shell
compile_lua_fuzzer lua lua-example fuzz_basic.lua
```

Arguments are:

* a Lua runtime name
* relative path of the project in the $SRC directory
* relative path to the fuzz test inside the project

The [lua-example](https://github.com/google/oss-fuzz/blob/master/projects/lua-example/build.sh)
project contains an example of a `build.sh` for a Lua projects.

## FuzzedDataProvider

luzer provides a `FuzzedDataProvider` that can simplify the task of creating a
fuzz target by translating the raw input bytes received from the fuzzer into
useful primitive Lua types. Its functionality is similar to
`FuzzedDataProviders` available in other languages, such as
[Java](https://codeintelligencetesting.github.io/jazzer-docs/jazzer-api/com/code_intelligence/jazzer/api/FuzzedDataProvider.html) and
[C++](https://github.com/google/fuzzing/blob/master/docs/split-inputs.md).

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
