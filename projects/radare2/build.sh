#!/bin/bash -eu

export USERCC=$CC
export HOST_CC=$CC

sys/static.sh
cp -r r2-static $OUT/

cp -r ../radare2-fuzz/targets .
export RADARE2_STATIC_BUILD=$OUT/r2-static

cd targets 
make

for target in $(ls *.cc); do
	fuzzer=$(echo $target | cut -d'.' -f1)
	cp $fuzzer $OUT
	cp $SRC/default.options $OUT/$fuzzer.options
done

for seed in $(ls corpora); do
	zip -j corpora/$seed.zip corpora/$seed/*
	cp corpora/$seed.zip $OUT
done
