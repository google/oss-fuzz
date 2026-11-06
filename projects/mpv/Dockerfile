# Copyright 2024 Google LLC
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

FROM gcr.io/oss-fuzz-base/base-builder-rust:ubuntu-24-04

RUN apt-get update && \
    apt-get install --no-install-recommends -y nasm pkgconf gperf zip rsync && \
    apt-get clean -y

ENV PYTHONDONTWRITEBYTECODE=1
ENV VIRTUAL_ENV=/opt/venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

RUN python -m venv $VIRTUAL_ENV && \
    python -m pip --no-cache-dir install meson ninja

RUN git clone --depth 1 https://github.com/mpv-player/mpv mpv
# Fuzz Introspector analyses every source file in $SRC before build.sh runs
# Keep only the mpv source visible and the rest without a checkout
RUN git clone --depth 1 --no-checkout https://github.com/FFmpeg/FFmpeg ffmpeg
RUN git clone --depth 1 --no-checkout https://github.com/haasn/libplacebo mpv/subprojects/libplacebo
RUN git clone --depth 1 --no-checkout https://github.com/libass/libass mpv/subprojects/libass
RUN mkdir mpv/subprojects -p && cd mpv && \
    meson wrap install expat && \
    meson wrap install fontconfig && \
    meson wrap install freetype2 && \
    meson wrap install fribidi && \
    meson wrap install harfbuzz && \
    meson wrap install lcms2 && \
    meson wrap install uchardet && \
    meson wrap install xxhash && \
    meson subprojects download && \
    meson subprojects purge --confirm

WORKDIR $SRC/mpv
COPY build.sh $SRC/
