# Dockerfile for OSS-Fuzz.
# In practice the canonical Dockerfile lives in google/oss-fuzz at
# projects/zhhz/Dockerfile; this copy exists here so the project's
# own repo carries the same definition and reviewers can audit it
# without jumping between repos.
#
# Use the OSS-Fuzz Rust base image — it has nightly Rust, cargo-fuzz,
# and the libFuzzer runtime pre-installed and pinned to a toolchain
# that still supports `-Z sanitizer=undefined` (which rustc removed
# from upstream nightlies after ~2024-11).
FROM gcr.io/oss-fuzz-base/base-builder-rust

# zhhz has no system-level build deps; everything is in the base image
# plus cargo dependencies fetched during build.sh.
