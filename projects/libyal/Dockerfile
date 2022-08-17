# Copyright 2020 Google Inc.
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

RUN apt-get update && apt-get install -y make autoconf automake autopoint libtool pkg-config flex byacc

RUN git clone --depth 1 https://github.com/libyal/libfmos.git libfmos
RUN git clone --depth 1 https://github.com/libyal/libfplist.git libfplist
RUN git clone --depth 1 https://github.com/libyal/libftxf.git libftxf
RUN git clone --depth 1 https://github.com/libyal/libfusn.git libfusn
RUN git clone --depth 1 https://github.com/libyal/libfwevt.git libfwevt
RUN git clone --depth 1 https://github.com/libyal/libfwnt.git libfwnt
RUN git clone --depth 1 https://github.com/libyal/libfwps.git libfwps
RUN git clone --depth 1 https://github.com/libyal/libfwsi.git libfwsi

RUN git clone --depth 1 https://github.com/libyal/libagdb.git libagdb
RUN git clone --depth 1 https://github.com/libyal/libcreg.git libcreg
RUN git clone --depth 1 https://github.com/libyal/libesedb.git libesedb
RUN git clone --depth 1 https://github.com/libyal/libevt.git libevt
RUN git clone --depth 1 https://github.com/libyal/libevtx.git libevtx
RUN git clone --depth 1 https://github.com/libyal/libexe.git libexe
RUN git clone --depth 1 https://github.com/libyal/liblnk.git liblnk
RUN git clone --depth 1 https://github.com/libyal/libmdmp.git libmdmp
RUN git clone --depth 1 https://github.com/libyal/libmsiecf.git libmsiecf
RUN git clone --depth 1 https://github.com/libyal/libnk2.git libnk2
RUN git clone --depth 1 https://github.com/libyal/libolecf.git libolecf
RUN git clone --depth 1 https://github.com/libyal/libpff.git libpff
RUN git clone --depth 1 https://github.com/libyal/libregf.git libregf
RUN git clone --depth 1 https://github.com/libyal/libscca.git libscca

RUN git clone --depth 1 https://github.com/libyal/libwrc.git libwrc

RUN git clone --depth 1 https://github.com/libyal/libfsapfs.git libfsapfs
RUN git clone --depth 1 https://github.com/libyal/libfsext.git libfsext
RUN git clone --depth 1 https://github.com/libyal/libfsfat.git libfsfat
RUN git clone --depth 1 https://github.com/libyal/libfshfs.git libfshfs
RUN git clone --depth 1 https://github.com/libyal/libfsntfs.git libfsntfs
RUN git clone --depth 1 https://github.com/libyal/libfsxfs.git libfsxfs

RUN git clone --depth 1 https://github.com/libyal/libbde.git libbde
RUN git clone --depth 1 https://github.com/libyal/libluksde.git libluksde
RUN git clone --depth 1 https://github.com/libyal/libvsapm.git libvsapm
RUN git clone --depth 1 https://github.com/libyal/libvsgpt.git libvsgpt
RUN git clone --depth 1 https://github.com/libyal/libvshadow.git libvshadow
RUN git clone --depth 1 https://github.com/libyal/libvslvm.git libvslvm
RUN git clone --depth 1 https://github.com/libyal/libvsmbr.git libvsmbr

RUN git clone --depth 1 https://github.com/libyal/libewf.git libewf
RUN git clone --depth 1 https://github.com/libyal/libmodi.git libmodi
RUN git clone --depth 1 https://github.com/libyal/libodraw.git libodraw
RUN git clone --depth 1 https://github.com/libyal/libphdi.git libphdi
RUN git clone --depth 1 https://github.com/libyal/libqcow.git libqcow
RUN git clone --depth 1 https://github.com/libyal/libsmraw.git libsmraw
RUN git clone --depth 1 https://github.com/libyal/libvhdi.git libvhdi
RUN git clone --depth 1 https://github.com/libyal/libvmdk.git libvmdk

WORKDIR libyal
COPY build.sh $SRC/
