FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get -y install \
    python wget

# Install Bazelisk
RUN wget -O /usr/local/bin/bazel https://github.com/bazelbuild/bazelisk/releases/download/v1.7.4/bazelisk-linux-amd64
RUN chmod +x /usr/local/bin/bazel

RUN git clone https://github.com/bazelbuild/rules_fuzzing.git
WORKDIR $SRC/rules_fuzzing/
COPY build.sh $SRC/
