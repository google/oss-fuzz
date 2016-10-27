# Building and Running Fuzzers

_This page documents building and running fuzzers as part of OSS target source tree._
_See [External Fuzzer](building_running_fuzzers_external.md) process for oss-fuzz fuzzers._

## Prerequisites

[Install Docker]. The toolchain setup necessary to build coverage-guided fuzzers is complicated. Docker is used
to simplify distribution of the toolchain and to produce repeatable results for distributed execution.

## Building Fuzzers

Building fuzzer is a two-step process:

1. Building a container ready to compile fuzzers: 
    <pre>
    <i># in target directory</i>
    docker build -t ossfuzz/<b><i>$target_name</i></b> .
    </pre>
2. Build fuzzers:
    <pre>
    <i># in target directory</i>
docker run -ti -v $PWD:/src/<b><i>$target_name</i></b> -v /tmp/out:/out ossfuzz/<b><i>$target_name</i></b>
    </pre>

`/tmp/out` will contain fuzzers.

## Running Fuzzers

Fuzzers are statically linked executables and could be executed normally in Unbuntu-like environment.
When Ubuntu environment is not aviable (or restricted environemnt is desirable), the fuzzer can easly be run inside docker 
container:

<pre>
docker run -ti -v /tmp/out:/out -t ossfuzz/libfuzzer-runner /out/<b><i>$fuzzer</i></b> --runs=100
</pre>

[Install Docker]: https://docs.docker.com/engine/installation/
