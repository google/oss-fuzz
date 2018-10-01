# Fuzzer environment on ClusterFuzz

Your fuzz targets will be run on a [Google Compute Engine](https://cloud.google.com/compute/) VM (Linux) with some security restrictions.

## Runtime Dependencies

You should not make any assumptions on the availability of dependent packages 
in the execution environment. Packages that are installed via
[Dockerfile](new_project_guide.md#dockerfile)
or built as part of 
[build.sh](new_project_guide.md#buildsh)
are not available on the bot runtime environment (where the fuzz targets run).

If you need these dependencies in the runtime environment, you can either
- Install the packages via Dockerfile
([example](https://github.com/google/oss-fuzz/blob/master/projects/tor/Dockerfile#L19))
and then link statically against them
([example](https://github.com/google/oss-fuzz/blob/master/projects/tor/build.sh#L40))
- Or build the dependencies statically in
[build.sh](new_project_guide.md#buildsh)
([example](https://github.com/google/oss-fuzz/blob/master/projects/ffmpeg/build.sh#L26)).

All build artifacts needed during fuzz target execution should be inside the `$OUT`
directory. Only those artifacts are archived and used on the bots. Everything else
is ignored (e.g. artifacts in `$WORK`, `$SRC`, etc) and hence is not available
in the execution environment.

You should ensure that the fuzz target works correctly by using `run_fuzzer` command 
(see instructions [here](new_project_guide.md#testing-locally)). This command uses
a clean base-runner docker container and not the base-builder docker container
created during build-time.

## argv[0]

You must not modify `argv[0]`. It is required for certain things to work correctly.

## Current working directory

You should not make any assumptions about the current working directory of your
fuzz target. If you need to load data files, please use `argv[0]` to get the
directory where your fuzz target executable is located.

## File system

Everything except `/tmp` is read-only, including the directory that your fuzz target
executable lives in.

`/dev` is also unavailable.

## Hardware

Your project should not be compiled with `-march=native` or `-mtune=native`
flags, as the build infrastructure and fuzzing machines may have different CPUs
as well as other hardware differences. You may however use `-mtune=generic`.
