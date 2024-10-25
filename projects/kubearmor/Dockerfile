FROM gcr.io/oss-fuzz-base/base-builder-go
ENV FUZZING_LANGUAGE=go
RUN git clone https://github.com/kubearmor/KubeArmor
COPY build.sh $SRC/
WORKDIR $SRC/KubeArmor/KubeArmor