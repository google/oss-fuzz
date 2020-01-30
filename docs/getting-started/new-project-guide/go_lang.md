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
[libFuzzer compatible mode](https://github.com/dvyukov/go-fuzz#libfuzzer-support)
only. In that mode, fuzz targets for Go use the libFuzzer engine with native Go
coverage instrumentation. Binaries compiled in this mode provide the same
libFuzzer command line interface as non-Go fuzz targets.

## Project files

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

The OSS-Fuzz builder image has the latest stable release of Golang installed. In
order to install dependencies of your project, add `RUN go get ...` command to
your Dockerfile.
[Example](https://github.com/google/oss-fuzz/blob/356f2b947670b7eb33a1f535c71bc5c87a60b0d1/projects/syzkaller/Dockerfile#L23):

```dockerfile
# Dependency for one of the fuzz targets.
RUN go get github.com/ianlancetaylor/demangle
```

### build.sh

In order to build a Go fuzz target, you need to call `go-fuzz-build -libfuzzer`
command first, and then link the resulting `.a` file against
`$LIB_FUZZING_ENGINE` using the `$CXX $CXXFLAGS ...` command.
[Example](https://github.com/google/oss-fuzz/blob/356f2b947670b7eb33a1f535c71bc5c87a60b0d1/projects/syzkaller/build.sh#L19):

```sh
function compile_fuzzer {
  path=$1
  function=$2
  fuzzer=$3

   # Instrument all Go files relevant to this fuzzer
  go-fuzz-build -libfuzzer -func $function -o $fuzzer.a $path 

   # Instrumented, compiled Go ($fuzzer.a) + fuzzing engine = fuzzer binary
  $CXX $CXXFLAGS $LIB_FUZZING_ENGINE $fuzzer.a -lpthread -o $OUT/$fuzzer
}

compile_fuzzer ./pkg/compiler Fuzz compiler_fuzzer
compile_fuzzer ./prog/test FuzzDeserialize prog_deserialize_fuzzer
```
