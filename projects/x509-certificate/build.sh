#!/bin/bash -eu

cd $SRC/cryptography-rs/x509-certificate

# Build fuzz targets
cargo fuzz build -O --debug-assertions

# Copy fuzz targets to output directory
FUZZ_TARGET_OUTPUT_DIR=$SRC/cryptography-rs/x509-certificate/fuzz/target/x86_64-unknown-linux-gnu/release
for f in fuzz_certificate_der fuzz_certificate_pem fuzz_time_parsing fuzz_csr_parse fuzz_name_parsing fuzz_extensions; do
    cp $FUZZ_TARGET_OUTPUT_DIR/$f $OUT/
done

# Copy seed corpus if it exists
if [ -d fuzz/corpus ]; then
    for target in fuzz_certificate_der fuzz_certificate_pem fuzz_time_parsing fuzz_csr_parse fuzz_name_parsing fuzz_extensions; do
        if [ -d fuzz/corpus/$target ]; then
            zip -r $OUT/${target}_seed_corpus.zip fuzz/corpus/$target/
        fi
    done
fi

# Copy dictionary if it exists
if [ -f fuzz/fuzz.dict ]; then
    cp fuzz/fuzz.dict $OUT/fuzz_time_parsing.dict
    cp fuzz/fuzz.dict $OUT/fuzz_certificate_der.dict
    cp fuzz/fuzz.dict $OUT/fuzz_certificate_pem.dict
fi
