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

FROM gcr.io/oss-fuzz-base/base-builder
# python3/asciidoctor: needed by any git checkout build of tcpreplay, not
# just when editing a *_opts.def - they regenerate the AutoOpts CLI parsers
# and man pages that release tarballs ship pre-built but a git clone does
# not.
# libdumbnet-dev: Debian/Ubuntu's package name for libdnet, which fragroute
# needs; build.sh reads the actual link flag back out of the project's own
# generated Makefile rather than guessing "-ldnet" or "-ldumbnet" here.
RUN apt-get update && apt-get install -y \
    automake autoconf libtool python3 asciidoctor libpcap-dev libdumbnet-dev zip
# Branch pinned to 4.6.1-beta1 rather than the default branch: the fuzz
# targets this builds haven't reached tcpreplay's master yet. Update this to
# drop "-b 4.6.1-beta1" (tracking the default branch again) once that
# release merges there - see the comment in project.yaml.
RUN git clone -b 4.6.1-beta1 --depth 1 https://github.com/appneta/tcpreplay.git tcpreplay
WORKDIR $SRC
COPY build.sh $SRC/
