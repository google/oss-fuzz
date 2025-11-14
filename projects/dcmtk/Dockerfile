FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y --no-install-recommends     cmake ninja-build make pkg-config zlib1g-dev python3 &&     rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/DCMTK/dcmtk $SRC/dcmtk
RUN git clone --depth 1 https://github.com/DCMTK/dcmtk-fuzzers $SRC/dcmtk-fuzzers

COPY build.sh $SRC/
COPY dcmtk_dicom_fuzzer.dict make_seed_corpus.py $SRC/dcmtk-fuzzers/
COPY dcmtk_dicom_fuzzer.cc dcmtk_meta_fuzzer.cc $SRC/dcmtk-fuzzers/

WORKDIR $SRC/dcmtk-fuzzers
