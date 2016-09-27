Fuzzing expat
=============

[http://expat.sourceforge.net/](http://expat.sourceforge.net/)

To build fuzzers: builde the image and run it:
````bash
git clone https://github.com/google/oss-fuzz.git
git clone git://git.code.sf.net/p/expat/code_git expat
docker build -t ossfuzz/expat oss-fizz/expat && \
docker run -i -v $PWD/oss-fuzz:/src/oss-fuzz -v $PWD/expat:/src/expat -v $HOME/tmp/out:/out -t ossfuzz/expat
````
Fuzzers will be in `$HOME/tmp/out`.


