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

RUN apt-get update && \
    apt-get install -y ffmpeg python3-pip gtk-doc-tools libffi-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
RUN pip3 install --disable-pip-version-check --no-cache-dir \
        pip==25.1.1
RUN pip3 install --disable-pip-version-check --no-cache-dir \
        corpus-replicator \
        meson==1.8.2 \
        ninja==1.11.1.4

RUN git clone --depth=1 --no-tags https://gitlab.gnome.org/GNOME/gdk-pixbuf.git
RUN git clone --depth=1 --branch=2.84.3 https://gitlab.gnome.org/GNOME/glib.git

RUN corpus-replicator -o corpus image_gif_gif_ffmpeg.yml image_jpg_jpg_ffmpeg.yml image_png_png_ffmpeg.yml image
RUN git clone --depth=1 --no-tags https://github.com/glennrp/libpng.git && \
    find $SRC/gdk-pixbuf/tests/ \( -name '*.jpeg' -o -name '*.jpg' -o -name '*.png' \) -exec cp -v '{}' corpus/ ';' && \
    find $SRC/libpng -name "*.png" | grep -v crashers | xargs cp -t corpus/ && \
    zip -q $SRC/gdk-pixbuf_seed_corpus.zip corpus/* && \
    rm -rf libpng corpus

ADD https://raw.githubusercontent.com/google/fuzzing/master/dictionaries/png.dict $SRC/png.dict
ADD https://raw.githubusercontent.com/google/fuzzing/master/dictionaries/jpeg.dict $SRC/jpeg.dict
ADD https://raw.githubusercontent.com/google/fuzzing/master/dictionaries/gif.dict $SRC/gif.dict
RUN awk 1 $SRC/*.dict > $SRC/gdk-pixbuf.dict && \
    rm -f $SRC/png.dict $SRC/jpeg.dict $SRC/gif.dict

WORKDIR $SRC/gdk-pixbuf
COPY targets $SRC/fuzz
COPY build.sh run_tests.sh $SRC/
