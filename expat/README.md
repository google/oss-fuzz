Fuzzing expat
=============

[http://expat.sourceforge.net/](http://expat.sourceforge.net/)

To build fuzzers: builde the image and run it:
````bash
# Checkout sources into ~/src/oss-fuzz & ~/src/expat
docker build -t ossfuzz/expat expat && \
docker run -i -v ~/src/oss-fuzz:/src/oss-fuzz -v ~/src/expat:/src/expat -v ~/tmp/out:/out -t ossfuzz/expat
````
Fuzzers will be in `~/tmp/out`.


