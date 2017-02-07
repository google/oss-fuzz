# Fuzzer environment on ClusterFuzz

Your fuzz targets will be run on a [Google Compute Engine](https://cloud.google.com/compute/) VM (Linux) with some security restrictions.

## Dependencies

You should not make any assumptions on the availability of dependent packages 
and libraries in the execution environment. Make sure to statically link any
library dependencies with your fuzz target executable during build time 
([example](https://github.com/google/oss-fuzz/blob/master/projects/tor/build.sh#L40)).

Please note that it is not required to build all dependecies in
[build.sh](https://github.com/google/oss-fuzz/blob/master/docs/new_project_guide.md#buildsh).
You can install any build dependendcies via
[Dockerfile](https://github.com/google/oss-fuzz/blob/master/docs/new_project_guide.md#dockerfile)
([example](https://github.com/google/oss-fuzz/blob/master/projects/tor/Dockerfile#L19)),
but make sure that you link statically against them. Those dependecies will be
available only on a builder machine, not on the ones running the fuzzers.

All build artifacts needed during fuzz target execution should be inside `$OUT` 
directory. Other directories like `$WORK`, `$SRC` OR dependent packages installed
in build.sh will not be available.

You can ensure that the fuzz target works correctly by using `run_fuzzer` command 
(see instructions [here](new_project_guide.md#testing-locally)). This command uses
a clean base-runner docker container and not the base-builder docker container
created during build-time.

## argv[0]

You must not modify argv[0]. It is required for certain things to work correctly.

## Current working directory

You should not make any assumptions about the current working directory of your
fuzz target. If you need to load data files, please use `argv[0]` to get the
directory where your fuzz target executable is located.

## File system

Everything except `/tmp` is read-only, including the directory that your fuzz target
executable lives in.

`/dev` is also unavailable.

## Network access

There will be no network interfaces available (not even loopback).
