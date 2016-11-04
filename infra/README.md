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
| `build_image`   |
| `build_fuzzers` |
| `run_fuzzer`    |
| `coverage`      |
| `shell`         |
