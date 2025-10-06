FROM gcr.io/oss-fuzz-base/base-builder-jvm

RUN git clone --depth 1 https://github.com/google/gson

RUN cd gson && ./gradlew jar -x test

COPY build.sh /
COPY *.java /
WORKDIR /gson
