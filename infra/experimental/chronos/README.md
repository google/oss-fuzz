# Chronos: rebuilding OSS-Fuzz harnesses using cached builds

Chronos is a utility tooling to enable fast re-building of OSS-Fuzz projects
and analysis of projects' testing infrastructure. This is used by projects,
e.g. [OSS-Fuzz-gen](https://github.com/google/oss-fuzz-gen) to help speed up
valuation processes during fuzzing harness generation.

Chronos is focused on two features, rebuilding projects fast and running the tests of a given project.

## Rebuilding projects fast

Chronos enables rebuilding projects efficiently in contexts where only a small patch
needs to be evalualted in the target. This is achieved by running a replay build script
in the build container, similarly to how a regular `build_fuzzers` command would run, but
with the caveat that the replay build script only performs a subset of the operations
of the original `build.sh`.

The replay build scripts are constructed in two ways: manually or automatically.

### Automated rebuilds

Chronos support automated rebuilding by:

1. Calling into a `replay_build.sh` script during the building inside the container [here](https://github.com/google/oss-fuzz/blob/206656447b213fb04901d15122692d8dd4d45312/infra/base-images/base-builder/compile#L292-L296)
2. The `replay_build.sh` calls into `make_build_replayable.py`: [here](https://github.com/google/oss-fuzz/blob/master/infra/base-images/base-builder/replay_build.sh)
3. `make_build_replayable.py` adjusts the build environment to wrap around common commands, to avoid performing a complete run of `build.sh`: [here](https://github.com/google/oss-fuzz/blob/master/infra/base-images/base-builder/make_build_replayable.py).

### Manually provided replay builds

`replay_build.sh` above, is simply just a wrapper script around `build.sh` that aims to enable
fast rebuilding of the project. This `replay_build.sh` can, however, be overwritten in the Dockerfile
of the project's builder image. Examples of this is [php](https://github.com/google/oss-fuzz/blob/206656447b213fb04901d15122692d8dd4d45312/projects/php/replay_build.sh#L1) and [ffmpeg](https://github.com/google/oss-fuzz/blob/master/projects/ffmpeg/replay_build.sh#L1).

Providing a manual `replay_build.sh` is likely more efficient at build time and can help speed up the process. Automated replay build scripts can also be erroneous.


### Testing the validity of a replay build

The Chronos manager can use the `manager.py` to validate the validity of a
replay build for a given project:

```sh
python3 infra/experimental/chronos/manager.py check-test tinyobjloader
```

If the above command fails for the relevant project, then the replay build feature
does not work for the given project.

## Running tests of a project

The second part of Chronos is a feature to enable running the tests of a given
project. This is done by way of a script `run_tests.sh`. Samples of
this script include [jsonnet](https://github.com/google/oss-fuzz/blob/master/projects/jsonnet/run_tests.sh#L1) and [tinyobjloader](https://github.com/google/oss-fuzz/blob/master/projects/tinyobjloader/run_tests.sh#L1).


### Testing the validity of run_tests.sh

The Chronos manager can use the `manager.py` to validate the validity of a
`run_tests.sh` script:

```sh
python3 infra/experimental/chronos/manager.py
```


**Running tests of a project**

## Pre-built images.

Daily pre-built images are available at:

- `us-central1-docker.pkg.dev/oss-fuzz/oss-fuzz-gen/<PROJECT>-ofg-cached-address`
- `us-central1-docker.pkg.dev/oss-fuzz/oss-fuzz-gen/<PROJECT>-ofg-cached-coverage`

They can be used as drop-in replacements for the usual `gcr.io/oss-fuzz/<PROJECT>` images.

These images are generated in 2 ways:
- (Preferred) [Generate](https://github.com/google/oss-fuzz/blob/master/infra/base-images/base-builder/bash_parser.py)
  a replay build script that can be re-run alongside existing build artifacts,
  leveraging existing build system mechanisms to avoid rebuilding (e.g. running
  `make` twice should not actually rebuild everything). This is error-prone, so
  we validate the script works by running it.
- (Fallback, if the replay build script didn't work). We leverage
  [ccache](https://ccache.dev/), to provide a compiler cache. This is often not
  as fast as the replay build script, because some project builds spend
  significant time doing non-compiler tasks (e.g. checking out submodules,
  running configure scripts).

Note: this mechanism does not work for every single OSS-Fuzz project today. The
resulting image may either:
- Not provide much performance improvement compared with a normal image, or
- Not exist at all (if neither approach worked).

Stats from a recent run: <https://gist.github.com/oliverchang/abaf3a1106a2b923c0ac3a577410aaaa>
(Feb 3 2025).

## Usage locally

**Example 1: htslib**

From the OSS-Fuzz root

```sh
$ RUN_ALL=1 ./infra/experimental/chronos/build_cache_local.sh htslib c address
...
...
Vanilla compile time:
17
Replay worked
Replay compile time:
2
Ccache compile time: 
9
```


## Check tests

Another feature of Chronos is the ability to run tests in a replayed build.
This requires `run_tests.sh` to be available in the cached image at
`$SRC/run_tests.sh`.

Sample running:

```
$ git clone https://github.com/google/oss-fuzz
$ cd oss-fuzz
$ ./infra/experimental/chronos/check_tests.sh jsonnet
...
...
100% tests passed, 0 tests failed out of 10

Total Test time (real) = 119.80 sec
```

In order ot make the above work, the general approach is to have a
`run_tests.sh` script in the OSS-Fuzz project's folder, which is copied into
the main image.

Notice that the `run_tests.sh` is run from a cached image, meaning the
`run_tests.sh` is run after a run of building fuzzers.
