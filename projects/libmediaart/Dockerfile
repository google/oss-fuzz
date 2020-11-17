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

#libffi-dev libexpat1-dev libglib2.0-dev libgtk-3-dev libgirepository1.0-dev \

#RUN echo deb http://archive.ubuntu.com/ubuntu/ focal main restricted universe multiverse >> /etc/apt/sources.list
FROM gcr.io/oss-fuzz-base/base-builder
#RUN sed -i -e 's/xenial/focal/g' /etc/apt/sources.list
RUN apt-get update && apt-get install -y python3-pip gobject-introspection \
    libffi-dev libexpat1-dev pkg-config libffi-dev libexpat1-dev libgirepository1.0-dev \
    libgdk-pixbuf2.0-dev valac gtk-doc-tools libselinux1-dev zlib1g-dev
    #valac gtk-doc-tools libselinux1-dev zlib1g-dev
RUN pip3 install meson==0.55.3 ninja
RUN git clone --depth 1 --single-branch --branch fuzzing https://gitlab.gnome.org/ceyhunalp/libmediaart.git
ADD https://ftp.gnome.org/pub/gnome/sources/glib/2.64/glib-2.64.2.tar.xz $SRC
RUN git clone --depth 1 https://gitlab.gnome.org/GNOME/gdk-pixbuf.git
#RUN git clone --depth 1 https://github.com/madler/zlib.git
RUN git clone --depth 1 https://github.com/mozilla/mp4parse-rust.git && \
    mv mp4parse-rust/mp4parse/tests/*mp4 $SRC/libmediaart/seed_corpus && \
    mv mp4parse-rust/mp4parse_capi/tests/*mp4 $SRC/libmediaart/seed_corpus && \
    zip -q $SRC/libmediaart_seed_corpus.zip $SRC/libmediaart/seed_corpus/* && \
    rm -rf mp4parse-rust
WORKDIR $SRC/libmediaart
COPY build.sh $SRC/
