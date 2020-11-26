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
RUN apt-get update && apt-get install -y python3-pip pkg-config \
    valac gtk-doc-tools libffi-dev libexpat1-dev
RUN pip3 install meson==0.55.3 ninja

ADD https://ftp.gnome.org/pub/gnome/sources/glib/2.64/glib-2.64.2.tar.xz $SRC
RUN tar xvJf $SRC/glib-2.64.2.tar.xz
RUN git clone --depth 1 https://gitlab.gnome.org/GNOME/gdk-pixbuf.git
RUN git clone --depth 1 --single-branch --branch fuzzing https://gitlab.gnome.org/ceyhunalp/libmediaart.git

RUN git clone --depth 1 https://github.com/dvyukov/go-fuzz-corpus.git && \
    git clone --depth 1 https://github.com/MozillaSecurity/fuzzdata.git && \
    mkdir corpus && \
    mv go-fuzz-corpus/jpeg/corpus/* corpus/ && \
    mv go-fuzz-corpus/png/corpus/* corpus/ && \
    mv fuzzdata/samples/jpg/* corpus/ && \
    mv fuzzdata/samples/png/common/* corpus/ && \
    zip -q $SRC/libmediaart_seed_corpus.zip corpus/* && \
    rm -rf fuzzdata go-fuzz-corpus corpus
ADD https://raw.githubusercontent.com/google/fuzzing/master/dictionaries/png.dict $SRC/png.dict
ADD https://raw.githubusercontent.com/google/fuzzing/master/dictionaries/jpeg.dict $SRC/jpeg.dict
RUN awk 1 $SRC/*.dict > $SRC/libmediaart.dict && \
    rm -f $SRC/png.dict $SRC/jpeg.dict

WORKDIR $SRC/libmediaart
COPY build.sh $SRC/
