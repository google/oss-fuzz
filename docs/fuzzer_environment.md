# Fuzzer environment on ClusterFuzz

Your fuzzers will be run on a [Google Compute Engine](https://cloud.google.com/compute/) VM (Linux) with some security restrictions.

## Current working directory

You should not make any assumptions about the current working directory of your
fuzzer. If you need to load data files, please use `argv[0]` to get the
directory where your fuzzer executable is located.

## File system

Everything except `/tmp` is read-only, including the directory that your fuzzer
executable lives in. Note that `/tmp` is limited in size (64MB).

## Network access

There will be no network interfaces available (not even loopback).
