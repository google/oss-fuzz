# Fuzzer environment on ClusterFuzz

Your fuzzers will be run on a [Google Compute Engine](https://cloud.google.com/compute/) VM (Linux) with some security restrictions.

## Current working directory

You should not make any assumptions about the current working directory of your
fuzzer. However, if you need to load data files, you can assume that `/out` will contain
whatever your build scripts copied into `$OUT`.

## File system

Everything except `/tmp` is read-only, including the directory that your fuzzer
executable lives in. Note that `/tmp` is limited in size (64MB).

`/dev` is also unavailable.

## Network access

There will be no network interfaces available (not even loopback).
