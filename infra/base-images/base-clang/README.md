# base-builder-clang

## Regular build

```
docker build -t gcr.io/oss-fuzz-base/base-clang . 
```

## Full build 
For a build including all binaries and libraries, including with everything built against libcxx, do

```
docker build -t gcr.io/oss-fuzz-base/base-clang-full --build-arg FULL_LLVM_BUILD=1 . 
```