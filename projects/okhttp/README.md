Purpose
- Scaffold an OSS-Fuzz project for OkHttp (Java/Kotlin) using Jazzer.
- Use this as a starting point for your oss-fuzz fork under projects/okhttp.

Files
- Dockerfile: base on base-builder-java; installs Gradle and builds fuzz targets.
- build.sh: assembles classpath and copies jazzer targets to $OUT.
- fuzz/UrlFuzzer.java: example Jazzer fuzzer over OkHttp HttpUrl parsing.

How to use
1) Fork https://github.com/google/oss-fuzz and create projects/okhttp/ with these files.
2) Ensure your OkHttp repo has the fuzz module (fuzz/) or copy it inside the Docker image.
3) Locally validate with OSS-Fuzz helper or trigger via Buttercup using fuzz_tooling_url/ref.

