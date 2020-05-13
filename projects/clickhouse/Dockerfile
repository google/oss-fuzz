FROM gcr.io/oss-fuzz-base/base-builder
MAINTAINER kyprizel@gmail.com

RUN apt-get update -y \
    && env DEBIAN_FRONTEND=noninteractive \
        apt-get install --yes --no-install-recommends \
            bash \
            wget \
            curl \
            expect \
            ninja-build \
            perl \
            pkg-config \
            python \
            python-lxml \
            python-requests \
            python-termcolor \
            sudo \
            tzdata


RUN wget https://github.com/Kitware/CMake/releases/download/v3.17.2/cmake-3.17.2-Linux-x86_64.sh; \
    chmod +x cmake-3.17.2-Linux-x86_64.sh; \
    ./cmake-3.17.2-Linux-x86_64.sh --skip-license --prefix="/usr"

RUN git clone --recursive https://github.com/ClickHouse/ClickHouse ClickHouse
WORKDIR ClickHouse

RUN sed -i s/'else ()'/'elseif (SANITIZE STREQUAL "coverage")\n    else ()'/ cmake/sanitize.cmake
RUN sed -i -e 's/add_warning(/no_warning(/g' src/CMakeLists.txt

COPY build.sh $SRC/
