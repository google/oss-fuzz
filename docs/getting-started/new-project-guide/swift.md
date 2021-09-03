---
layout: default
title: Integrating a Swift project
parent: Setting up a new project
grand_parent: Getting started
nav_order: 1
permalink: /getting-started/new-project-guide/swift/
---

# Integrating a Swift project
{: .no_toc}

- TOC
{:toc}
---

The process of integrating a project written in Swift with OSS-Fuzz is very similar
to the general
[Setting up a new project]({{ site.baseurl }}/getting-started/new-project-guide/)
process. The key specifics of integrating a Swift project are outlined below.

## Project files

First, you need to write a Swift fuzz target that accepts a stream of bytes and
calls the program API with that. This fuzz target should reside in your project
repository.

The structure of the project directory in OSS-Fuzz repository doesn't differ for
projects written in Swift. The project files have the following Swift specific
aspects.

### project.yaml

The `language` attribute must be specified.

```yaml
language: swift
```

The only supported fuzzing engine is `libfuzzer`

The supported sanitizers are and `address`, `thread`

[Example](https://github.com/google/oss-fuzz/blob/2a15c3c88b21f4f1be2a7ff115f72bd7a08e34ac/projects/swift-nio/project.yaml#L9):

```yaml
fuzzing_engines:
  - libfuzzer
sanitizers:
  - address
  - thread
```

### Dockerfile

The Dockerfile should start by `FROM gcr.io/oss-fuzz-base/base-builder-swift`
instead of using the simple base-builder

### build.sh

A `precompile_swift` generates an environment variable `SWIFTFLAGS`
This can then be used in the building command such as `swift build -c release $SWIFTFLAGS`


A usage example from swift-protobuf project is

```sh
. precompile_swift
# build project
cd FuzzTesting
swift build -c debug $SWIFTFLAGS

(
cd .build/debug/
find . -maxdepth 1 -type f -name "*Fuzzer" -executable | while read i; do cp $i $OUT/"$i"-debug; done
)

```
