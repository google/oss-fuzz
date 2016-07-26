Fuzzing expat
=============

[http://expat.sourceforge.net/](http://expat.sourceforge.net/)

Building and running:
````bash
# Checkout sources into ~/src/oss-fuzz & ~/src/expat
docker build -t ossfuzz/expat expat && \
docker run -i -v ~/src/oss-fuzz:/src/oss-fuzz -v ~/src/expat:/workspace -t ossfuzz/expat
````
