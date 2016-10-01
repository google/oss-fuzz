# Building and Running Fuzzers

_This page documents building and running fuzzers as part of an OSS project._
_See [External Fuzzer](building_running_fuzzers_external.md) process for oss-fuzz fuzzers._

## Prerequisites

[Install Docker]. The toolchain setup necessary to build coverage-guided fuzzers is complicated. Docker is used
to simplify distribution of the toolchain and to produce repeatable results for distributed execution.

## Building Fuzzers

Building fuzzer is a two-step process:

1. Building a container ready to compile fuzzers: 
````bash
# in project directory; replace/define PROJECT_NAME
docker build -t ossfuzz/$PROJECT_NAME .
````
2. Running a container:
````bash
# in project directory; replace/define PROJECT_NAME
docker run -ti -v $PWD:/src/$PROJECT_NAME -v /tmp/out:/out ossfuzz/$PROJECT_NAME
````

`/tmp/out` will contain fuzzers.

## Running Fuzzers

Fuzzers are statically linked executables and could be executed normally in Unbuntu-like environment.
When Ubuntu environment is not aviable (or restricted environemnt is desirable), the fuzzer can easly be run inside docker 
container:

````bash
docker run -ti -v /tmp/out:/out -t ossfuzz/libfuzzer-runner /out/some_fuzzer_name --runs=100
````

[Install Docker]: https://docs.docker.com/engine/installation/
