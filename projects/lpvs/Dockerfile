FROM gcr.io/oss-fuzz-base/base-builder-jvm

RUN curl -L https://archive.apache.org/dist/maven/maven-3/3.9.6/binaries/apache-maven-3.9.6-bin.zip -o maven.zip && \
    unzip maven.zip -d $SRC/maven && \
    rm -rf maven.zip

ENV MVN $SRC/maven/apache-maven-3.9.6/bin/mvn

RUN git clone --depth 1 https://github.com/samsung/lpvs

COPY . $SRC

# WORKDIR 
WORKDIR $SRC/

#COPY build.sh $SRC/
COPY build.sh $SRC/
