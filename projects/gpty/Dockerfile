# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

# gPTY is a Rust + Godot multi-PTY emulator. The fuzz targets cover the
# ANSI/OSC escape parser, the terminal grid and capture path, the control
# socket's request decode, the AI child's frame reader, the Markdown renderer,
# vault link scanning and the media probe.
FROM gcr.io/oss-fuzz-base/base-builder-rust:ubuntu-24-04

# scripts/media-deps builds the pinned FFmpeg that gpty-media links: nasm
# enables the x86 SIMD assembly, and clang + libclang-dev are what
# ffmpeg-sys-the-third's bindgen needs. zip packages the seed corpora.
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential clang libclang-dev nasm pkg-config zip \
    && rm -rf /var/lib/apt/lists/*

# The project's rust-toolchain.toml pins a stable release, which cannot build a
# sanitizer target; cargo fuzz needs nightly. Pin the nightly gpty's own fuzz
# CI job builds with.
ENV RUSTUP_TOOLCHAIN=nightly-2026-11-01
RUN rustup toolchain install "$RUSTUP_TOOLCHAIN" --profile minimal

RUN git clone --depth 1 https://github.com/godot-pty/gpty.git gpty
WORKDIR $SRC/gpty

# The exact FFmpeg the project ships (SHA256-pinned by scripts/media-deps).
# Its source and build trees are not needed after the install.
RUN ./scripts/media-deps \
    && rm -rf dist/ffmpeg/src dist/ffmpeg/build-linux-x86_64

COPY build.sh $SRC/
