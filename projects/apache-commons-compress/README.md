Note that classes that use third party libraries are excluded.
These are either being already fuzzed by oss-fuzz or cannot be
fuzzed effectively. These include:
* BrotliCompressorInputStream - uses Google's Brotli
* DeflateCompressorInputStream - uses JDK's Inflater
* LZMACompressorInputStream - uses XZ for Java
* XZCompressorInputStream - uses XZ for Java
* ZstdCompressorInputStream - uses zstd-jni
