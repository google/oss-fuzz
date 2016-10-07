# base-libfuzzer
> Abstract base image for libfuzzer builders.

Supported commands:

* `docker run -ti <image_name> [compile]` - compiles everything. Expects /src/ paths
  to be mounted.

# Child Image Interface

## Required Files

Following files have to be added by child images:

| File Location | Description |
| ------------- | ----------- |
| `/src/build.sh` | build script to build the library and its fuzzers |

# Image Layout

| Location | Description |
| -------- | ----------  |
| `/src/build.sh` | build script for the project |
| `/src/<project>` | checked out sources for the project;  mounted when run |
| `/out/` | build artifacts should be copied here  |
| `/work/` | used to store intermediate files |
