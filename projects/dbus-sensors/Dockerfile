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

FROM gcr.io/oss-fuzz-base/base-builder:ubuntu-24-04

ENV BUILD_REVISION=9

RUN apt-get update && apt-get install -y \
    make \
    cmake \
    pkg-config \
    libssl-dev \
    libboost-dev \
    libboost-system-dev \
    libboost-coroutine-dev \
    libboost-context-dev \
    libsystemd-dev \
    libdbus-1-dev \
    systemd \
    nlohmann-json3-dev \
    ninja-build \
    python3-pip \
    python3-inflection \
    python3-jinja2 \
    python3-mako \
    python3-yaml && \
    pip3 install meson inflection mako pyyaml jsonschema --break-system-packages && \
    mkdir -p /usr/share/pkgconfig && \
    printf 'Name: systemd\nDescription: systemd\nVersion: 245\nsystemd_system_unit_dir=/lib/systemd/system\nsystemduserunitdir=/usr/lib/systemd/user\nsystemdsystemunitdir=/lib/systemd/system\n' > /usr/share/pkgconfig/systemd.pc

RUN printf '#pragma once\n#include <type_traits>\n#include <functional>\nnamespace std { template <typename Arg, typename Result> struct unary_function { typedef Arg argument_type; typedef Result result_type; }; template <typename Arg1, typename Arg2, typename Result> struct binary_function { typedef Arg1 first_argument_type; typedef Arg2 second_argument_type; typedef Result result_type; }; template <typename F> struct result_of; template <typename F, typename... Args> struct result_of<F(Args...)> : std::invoke_result<F, Args...> {}; }\n' > $SRC/boost_compat.h

RUN git clone --depth 1 https://github.com/openbmc/sdbusplus $SRC/sdbusplus && \
    sed -i 's/std::move_only_function/std::function/g' $SRC/sdbusplus/include/sdbusplus/asio/connection.hpp && \
    sed -i '1s/^/#include <unistd.h>\n/' $SRC/sdbusplus/include/sdbusplus/event.hpp && \
    meson setup $SRC/sdbusplus/build $SRC/sdbusplus -Ddefault_library=static -Dwerror=false -Dtests=disabled -Dexamples=disabled '-Dcpp_args=["-stdlib=libc++"]' '-Dcpp_link_args=["-stdlib=libc++", "-pthread"]' && \
    ninja -C $SRC/sdbusplus/build install && \
    sed -i 's/std::move_only_function/std::function/g' /usr/local/include/sdbusplus/asio/connection.hpp && \
    sed -i '1s/^/#include <unistd.h>\n/' /usr/local/include/sdbusplus/event.hpp

RUN git clone --depth 1 https://github.com/openbmc/phosphor-logging $SRC/phosphor-logging && \
    mkdir -p /usr/local/include/phosphor-logging && \
    find $SRC/phosphor-logging -type f -name "*.hpp" -exec cp {} /usr/local/include/phosphor-logging/ \; && \
    find $SRC/phosphor-logging -type d -name "lg2" -exec cp -r {} /usr/local/include/phosphor-logging/ \; && \
    mkdir -p /usr/local/lib && \
    printf '#include <source_location>\nnamespace lg2 {\nenum class level { emergency, alert, critical, error, warning, notice, info, debug };\nnamespace details {\nvoid do_log(level, const std::source_location&, const char*, ...) {}\n}\n}\n' > $SRC/lg2_stub.cpp && \
    clang++ -O2 -std=c++23 -stdlib=libc++ -c $SRC/lg2_stub.cpp -o $SRC/lg2_stub.o && \
    ar rcs /usr/local/lib/libphosphor_logging.a $SRC/lg2_stub.o && \
    printf 'Name: phosphor-logging\nDescription: phosphor-logging\nVersion: 1.0.0\nCflags: -I/usr/local/include\nLibs: -L/usr/local/lib -lphosphor_logging\n' > /usr/share/pkgconfig/phosphor-logging.pc

RUN git clone --depth 1 https://github.com/openbmc/dbus-sensors $SRC/dbus-sensors

WORKDIR $SRC/dbus-sensors
COPY build.sh utils_fuzzer.cpp $SRC/
