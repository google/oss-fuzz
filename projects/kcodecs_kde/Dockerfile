FROM fedora:38
RUN dnf update -y && dnf install -y \
    clang \
    clang-tools-extra \
    llvm-libs \
    cmake \
    git \
    make \
    gcc \
    gcc-c++ \
    libstdc++-devel \
    libasan \
    libubsan \
    kf5-kcodecs-devel \
    qt5-qtbase-devel \
    qt5-qtxmlpatterns-devel \
    pkgconfig \
    findutils
WORKDIR /src
COPY build.sh /src/
COPY kcodecs_fuzzer.cc /src/
COPY corpus.tar.gz /src/
ENV FUZZER_NAME=kcodecs_fuzzer
RUN chmod +x build.sh
RUN bash build.sh
# ENTRYPOINT ["./build.sh"]
