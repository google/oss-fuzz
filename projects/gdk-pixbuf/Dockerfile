# Copyright 2018 Google Inc.
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
RUN sed -i -e 's/xenial/focal/g' /etc/apt/sources.list
RUN apt-get update && apt-get install -y python3-pip gobject-introspection libglib2.0-dev libgtk-3-dev libgirepository1.0-dev gtk-doc-tools libc6-dev
RUN pip3 install -U meson ninja
RUN git clone --depth 1 --single-branch --branch fuzzing https://gitlab.gnome.org/ceyhunalp/gdk-pixbuf.git
WORKDIR $SRC/gdk-pixbuf
COPY build.sh $SRC/
