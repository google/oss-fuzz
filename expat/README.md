Fuzzing expat
=============

[http://expat.sourceforge.net/](http://expat.sourceforge.net/)

To build fuzzers: build and run the docker image:
````bash
# Checkout sources
git clone https://github.com/google/oss-fuzz.git
git clone git://git.code.sf.net/p/expat/code_git expat
# Build & run the image.
docker build -t ossfuzz/expat oss-fizz/expat && \
docker run -i -v $PWD/expat:/src/expat -v $HOME/tmp/out:/out -t ossfuzz/expat
````
Fuzzers will be in `$HOME/tmp/out`.


