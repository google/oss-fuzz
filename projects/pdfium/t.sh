# temporary script for quick shorthands inside oss-fuzz docker env.
rm -rf ./out/fuzzers7/
mkdir -p out/fuzzers7
cp $SRC/args.gn ./out/fuzzers7/args.gn
gn gen out/fuzzers7/
ninja -C out/fuzzers7 pdf_formcalc_context_fuzzer

