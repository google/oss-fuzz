# Copyright 2025 Google LLC
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

FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y python3-pip ninja-build libbrotli-dev libkrb5-dev libnghttp2-dev libpsl-dev libidn2-dev libsqlite3-dev
RUN pip3 install --root-user-action=ignore --break-system-packages meson

# version in 20.04 is too old.
RUN git clone --depth 1 https://gitlab.gnome.org/GNOME/glib.git --branch=glib-2-82 && \
  meson setup _build glib --prefix=/usr -Ddefault_library=static -Dtests=false && \
  meson install -C _build && \
  rm -rf glib _build

RUN git clone --depth 1 https://gitlab.gnome.org/GNOME/libsoup.git && sed -i -e "s/version : glib_required_version/version : glib_required_version, static: true/" -e "s/subdir('examples')//" libsoup/meson.build
WORKDIR libsoup

COPY build.sh $SRC/
