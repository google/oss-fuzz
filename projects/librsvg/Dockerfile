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
#
################################################################################

FROM gcr.io/oss-fuzz-base/base-builder-rust

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install --no-install-recommends -y \
        gperf \
        pkg-config && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
RUN pip3 install --disable-pip-version-check --no-cache-dir \
        pip==24.2
RUN pip3 install --disable-pip-version-check --no-cache-dir \
        meson==1.5.1 \
        ninja==1.11.1.1 \
        packaging==24.1

# We have to compile various dependencies because the distro does not have recent enough
# versions of packages like Pango. Manual compilation also makes it easier to use static linking:
# https://google.github.io/oss-fuzz/further-reading/fuzzer-environment/

RUN git clone --depth=1 --no-tags https://gitlab.gnome.org/GNOME/librsvg.git
RUN git clone --depth=1 --branch=2.82.0 https://gitlab.gnome.org/GNOME/glib.git
RUN git clone --depth=1 --branch=VER-2-13-3 https://gitlab.freedesktop.org/freetype/freetype.git
RUN git clone --depth=1 --branch=v2.13.3 https://gitlab.gnome.org/GNOME/libxml2.git
RUN git clone --depth=1 --branch=2.15.0 https://gitlab.freedesktop.org/fontconfig/fontconfig.git
RUN git clone --depth=1 --branch=1.18.2 https://gitlab.freedesktop.org/cairo/cairo.git
RUN git clone --depth=1 --branch=9.0.0 https://github.com/harfbuzz/harfbuzz.git
RUN git clone --depth=1 --branch=1.54.0 https://gitlab.gnome.org/GNOME/pango.git

RUN git clone --depth=1 --no-tags https://github.com/google/fuzzing.git

COPY build.sh *.options "$SRC/"

WORKDIR "$SRC/librsvg"
