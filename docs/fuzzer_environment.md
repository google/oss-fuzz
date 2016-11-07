# Fuzzer environment on ClusterFuzz

Your fuzzers will be run on ClusterFuzz (Linux environment) with some
restrictions.

## Current working directory

You cannot make any assumptions about the current working directory of your
fuzzer. If you need to load data files, please use `argv[0]` to get the
directory where your fuzzer executable is located. This may change in the near
future.

## Filesystem

Everything except `/tmp` is read-only, including the directory that your fuzzer
executable lives in. Note that `/tmp` is limited in size (64MB).

## Network access

There will be no network interfaces available (not even loopback).
