FROM gcr.io/oss-fuzz-base/base-builder
MAINTAINER vincent.ulitzsch@live.de
RUN apt-get update && apt-get install -y make autoconf automake libtool wget zlib1g-dev
RUN apt-get update && \
apt-get install -y  libtool ninja-build cmake subversion
RUN apt-get install -y libstdc++6
RUN svn co https://svn.apache.org/repos/asf/xerces/c/trunk $SRC/xerces-c
RUN git clone --depth 1 https://github.com/google/libprotobuf-mutator.git
RUN (mkdir LPM && cd LPM && cmake ../libprotobuf-mutator -GNinja -DLIB_PROTO_MUTATOR_DOWNLOAD_PROTOBUF=ON -DLIB_PROTO_MUTATOR_TESTING=OFF -DCMAKE_BUILD_TYPE=Release && ninja)
COPY *.c *.options build.sh *.h *.cc *.cpp *.proto $SRC/
