---
layout: default
title: Fuzzer environment
parent: Further reading
nav_order: 2
permalink: /further-reading/fuzzer-environment/
---

# Fuzzer environment on ClusterFuzz

Your fuzz targets will be run on a
[Google Compute Engine](https://cloud.google.com/compute/) VM (Linux).

- TOC
{:toc}
---

## Runtime Dependencies

You should not make any assumptions on the availability of dependent packages 
in the execution environment. Packages that are installed via
[Dockerfile]({{ site.baseurl }}/getting-started/new-project-guide/#dockerfile)
or built as part of 
[build.sh]({{ site.baseurl }}/getting-started/new-project-guide/#buildsh)
are not available on the bot runtime environment (where the fuzz targets run).

If you need these dependencies in the runtime environment, you can either:
- Install the packages via Dockerfile
([example](https://github.com/google/oss-fuzz/blob/2d5e2ef84f281e6ab789055aa735606d3122fda9/projects/tor/Dockerfile#L19))
and then link statically against them
([example](https://github.com/google/oss-fuzz/blob/2d5e2ef84f281e6ab789055aa735606d3122fda9/projects/tor/build.sh#L40)).
- Or build the dependencies statically in
[build.sh]({{ site.baseurl }}/getting-started/new-project-guide/#buildsh)
([example](https://github.com/google/oss-fuzz/blob/64f8b6593da141b97c98c7bc6f07df92c42ee010/projects/ffmpeg/build.sh#L26)).

All build artifacts needed during fuzz target execution should be inside the
`$OUT` directory. Only those artifacts are archived and used on the bots.
Everything else is ignored (e.g. artifacts in `$WORK`, `$SRC`, etc) and hence
is not available in the execution environment.

We strongly recommend static linking because it just works. 
However dynamic linking can work if shared objects are included in the `$OUT` directory and are loaded relative
to `'$ORIGIN'`, the path of the binary (see the discussion of `'$ORIGIN'` [here](http://man7.org/linux/man-pages/man8/ld.so.8.html)).
A fuzzer can be instructed to load libraries relative to `'$ORIGIN'` during compilation (i.e. `-Wl,-rpath,'$ORIGIN/lib'` )
or afterwards using `chrpath -r '$ORIGIN/lib' $OUT/$fuzzerName` ([example](https://github.com/google/oss-fuzz/blob/09aa9ac556f97bd4e31928747eca0c8fed42509f/projects/php/build.sh#L40)). Note that `'$ORIGIN'` should be surrounded
by single quotes because it is not an environment variable like `$OUT` that can be retrieved during execution of `build.sh`.
Its value is retrieved during execution of the binary. You can verify that you did this correctly using `ldd <fuzz_target_name>` and the `check_build` command in `infra/helper.py`.

You should ensure that the fuzz target works correctly by using `run_fuzzer`
command (see instructions
[here]({{ site.baseurl }}/getting-started/new-project-guide/#testing-locally)).
This command uses a clean base-runner docker container and not the base-builder
docker container created during build-time.

## argv[0]

You must not modify `argv[0]`. It is required for certain things to work
correctly.

## Current working directory

You should not make any assumptions about the current working directory of your
fuzz target. If you need to load data files, please use `argv[0]` to get the
directory where your fuzz target executable is located.

## File system

Everything except `/tmp` is read-only, including the directory that your fuzz
target executable lives in.

`/dev` is also unavailable.

## Hardware

Your project should not be compiled with `-march=native` or `-mtune=native`
flags, as the build infrastructure and fuzzing machines may have different CPUs
as well as other hardware differences. You may however use `-mtune=generic`.
