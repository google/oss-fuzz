# infra
> OSS-Fuzz project infrastructure

Core infrastructure:
* [`base-images`](base-images/) - docker images for building fuzz targets & corresponding jenkins
  pipeline.

Continuous Integration infrastructure:

* [`ci`](ci/) - script to build projects in CI.

## helper.py
> script to automate common docker operations

| Command | Description |
|---------|-------------
| `generate`      | Generates skeleton files for a new project |
| `build_image`   | Builds a docker image for a given project |
| `build_fuzzers` | Builds fuzz targets for a given project |
| `run_fuzzer`    | Runs a fuzz target in a docker container |
| `coverage`      | Runs fuzz target(s) in a docker container and generates a code coverage report. See [Code Coverage doc](https://google.github.io/oss-fuzz/advanced-topics/code-coverage/) |
| `reproduce`     | Runs a testcase to reproduce a crash |
| `shell`         | Starts a shell inside the docker image for a project |
