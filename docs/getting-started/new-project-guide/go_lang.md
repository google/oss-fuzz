---
layout: default
title: Integrating a Go project
parent: Setting up a new project
grand_parent: Getting started
nav_order: 1
permalink: /getting-started/new-project-guide/go-lang/
---

# Integrating a Go project
{: .no_toc}

- TOC
{:toc}
---

The process of integrating a project written in Go with OSS-Fuzz is very similar
to the general
[Setting up a new project]({{ site.baseurl }}/getting-started/new-project-guide/)
process. The key specifics of integrating a Go project are outlined below.

## Go-fuzz support

OSS-Fuzz supports **go-fuzz** in the
[libFuzzer compatible mode](https://github.com/mdempsky/go114-fuzz-build)
only. In that mode, fuzz targets for Go use the libFuzzer engine with native Go
coverage instrumentation. Binaries compiled in this mode provide the same
libFuzzer command line interface as non-Go fuzz targets.

## Native Go Fuzzing support

OSS-fuzz supports [fuzzers written for the native Go 1.18 engine](https://go.dev/doc/fuzz/). These fuzzers are built as libFuzzer binaries in a similar fashion as fuzzers written for the go-fuzz engine. Because of that, dictionaries and seed corpora should be handled in accordance with [the OSS-fuzz documentation](https://google.github.io/oss-fuzz/getting-started/new-project-guide/#seed-corpus).
Unlike libFuzzer/go-fuzz targets which must accept one data buffer, fuzz targets written for the Native Go engine can accept any number of arguments of any type. Here is an example of a valid fuzzer with multiple arguments:

```go
package demofuzzing

import (
    "fmt"
    "testing"
)

func FuzzDemo(f *testing.F) {
    f.Fuzz(func(t *testing.T, data1 string, data2 uint32, data3 float64) {
        fmt.Println(data1)
        fmt.Println(data2)
        fmt.Println(data3)
    })
}
```

Some requirements for native Go 1.18 fuzzers are:
* The only `testing.F` method supported is currently `F.Fuzz()`.
* `F.Add()` will not add seeds when fuzzing. To provide OSS-fuzz with a seed corpus, follow the documentation [here](https://google.github.io/oss-fuzz/getting-started/new-project-guide/#seed-corpus).

## Project files

First, you need to write a Go fuzz target. This fuzz target should reside in your project
repository
([example](https://github.com/golang/go/blob/4ad13555184eb0697c2e92c64c1b0bdb287ccc10/src/html/fuzz.go#L13)).

The structure of the project directory in OSS-Fuzz repository doesn't differ for
projects written in Go. The project files have the following Go specific
aspects.

### project.yaml

The `language` attribute must be specified.

```yaml
language: go
```

The only supported fuzzing engine and sanitizer are `libfuzzer` and `address`,
respectively.
[Example](https://github.com/google/oss-fuzz/blob/356f2b947670b7eb33a1f535c71bc5c87a60b0d1/projects/syzkaller/project.yaml#L7):

```yaml
fuzzing_engines:
  - libfuzzer
sanitizers:
  - address
```

### Dockerfile

The Dockerfile should start by `FROM gcr.io/oss-fuzz-base/base-builder-go`

The OSS-Fuzz builder image has the latest stable release of Golang installed. In
order to install dependencies of your project, add `RUN git clone ...` command to
your Dockerfile.
[Example](https://github.com/google/oss-fuzz/blob/356f2b947670b7eb33a1f535c71bc5c87a60b0d1/projects/syzkaller/Dockerfile#L23):

```dockerfile
# Dependency for one of the fuzz targets.
RUN git clone --depth 1 https://github.com/ianlancetaylor/demangle
```

go-fuzz will then automatically download the dependencies based on the go.mod file

### build.sh

In order to build a Go fuzz target, you need to call `go-fuzz`
command first, and then link the resulting `.a` file against
`$LIB_FUZZING_ENGINE` using the `$CXX $CXXFLAGS ...` command.

For go-fuzz fuzzers, the best way to do this is by using the `compile_go_fuzzer` script, and for native Go 1.18 fuzzers it is recommended to use the `compile_native_go_fuzzer` script. Both of these also support coverage builds.

A usage example from go-dns project is

```sh
compile_go_fuzzer github.com/miekg/dns FuzzNewRR fuzz_newrr fuzz
```

Arguments are :
* path of the package with the fuzz target
* name of the fuzz function
* name of the fuzzer to be built
* optional tag to be used by `go build` and such
