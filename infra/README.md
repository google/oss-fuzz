# infra
> OSS-Fuzz project infrastructure

Core infrastructure:
* [`base-images`](base-images/) - docker images for building fuzzers & corresponding jenkins
  pipeline.
  
Continuous Integration infrastracture:

* [`libfuzzer-pipeline.groovy`](libfuzzer-pipeline.groovy/) - jenkins pipeline that runs for each oss-fuzz
  project.
* [`docker-cleanup`](docker-cleanup/) - jenkins pipeline to clean stale docker images & processes.
* [`push-images`](push-images/) - jenkins pipeline to push built base images.
* [`jenkins-cluster`](jenkins-cluster/) - kubernetes cluster definition for our jenkins-based build (not operational yet).

## helper.py
> script to automate common docker operations

| Command | Description |
|---------|-------------
| `generate`      | Generates skeleton files for a new target |
| `build_image`   | Builds a docker image for a given target |
| `build_fuzzers` | Builds fuzzers for a given target |
| `run_fuzzer`    | Runs a fuzzer in a docker container |
| `coverage`      | Runs a fuzzer in a docker container and computes a coverage report |
| `shell`         | Starts a shell inside the docker image for a target |
