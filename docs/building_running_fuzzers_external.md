# Building and Running External Fuzzers

_This page documents building and running fuzzers defined as part of oss-fuzz repository,
and not an original OSS project._
_See [Building and Running Fuzzers](building_running_fuzzers.md) process for in-repository fuzzers._

## Prerequisites

[Install Docker]. The toolchain setup necessary to build coverage-guided fuzzers is complicated. Docker is used
to simplify distribution of the toolchain and to produce repeatable results for distributed execution.

## Checkout

Checkout the oss-fuzz source tree as well as the project you are going to fuzz:
```bash
git clone git://github.com/google/oss-fuzz.git
# checkout the project into $PROJECT_NAME dir. e.g. 
# git clone git://git.sv.nongnu.org/freetype/freetype2.git freetype2
# export PROJECT_NAME=freetype2
```

## Building Fuzzers

Building fuzzer is a two-step process:

1. Building a container ready to compile fuzzers: 
````bash
docker build -t ossfuzz/$PROJECT_NAME oss-fuzz/$PROJECT_NAME
````
2. Running a container:
````bash
docker run -ti -v $PWD/$PROJECT_NAME:/src/$PROJECT_NAME -v /tmp/out:/out ossfuzz/$PROJECT_NAME
````

`/tmp/out` will contain fuzzers.

## Running Fuzzers

Fuzzers are statically linked executables and could be executed normally in Unbuntu-like environment:

```bash
$ /tmp/out/freetype2_fuzzer
INFO: Seed: 477892609
#0      READ   units: 1 exec/s: 0
#1      INITED cov: 29 bits: 2 indir: 14 units: 1 exec/s: 0
#2      NEW    cov: 289 bits: 280 indir: 61 units: 2 exec/s: 0 L: 64 MS: 0 
#3      NEW    cov: 291 bits: 280 indir: 61 units: 3 exec/s: 0 L: 64 MS: 1 ChangeBit-
#4      NEW    cov: 293 bits: 299 indir: 61 units: 4 exec/s: 0 L: 32 MS: 2 ChangeBit-EraseBytes-
```

When Ubuntu environment is not aviable (or restricted environemnt is desirable), the fuzzer can easly be run inside docker 
container:

````bash
docker run -ti -v /tmp/out:/out -t ossfuzz/libfuzzer-runner /out/some_fuzzer_name --runs=100
````

[Install Docker]: https://docs.docker.com/engine/installation/
