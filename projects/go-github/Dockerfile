FROM gcr.io/oss-fuzz-base/base-builder-go 
 
RUN git clone --depth 1 https://github.com/google/go-github 
WORKDIR go-github 
COPY build.sh $SRC/ 
