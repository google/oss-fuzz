# base-libfuzzer
> Abstract base image for libfuzzer builders.

Supported commands:

* `docker run -ti <image_name> [compile]` - compiles everything. Expects /src/ paths
  to be mounted.
* `docker run -ti <image_name> checkout_and_compile` - checks projects sources out 
  if its location is defined and compiles.
* `docker run -ti <image_name> /bin/bash` - drop into shell. Run `compile` script
  to start build. 

# Child Image Interface

## Required Files

Following files have to be added by child images:

| File Location | Description |
| ------------- | ----------- |
| `/src/build.sh` | build script to build the library and its fuzzers |

## Optional Environment Variables

Child image can define following environment variables:

| Variable | Description |
| -------- | ----------- |
| `GIT_URL` (optional) | git url for sources |
| `SVN_URL` (optional) | svn url for sources |
| `GIT_CHECKOUT_DIR` (optional) | directory (under `/src/`) to checkout into |
| `SVN_CHECKOUT_DIR` (optional) | directory (under `/src/`) to checkout into |

# Image Layout

| Location | Description |
| -------- | ----------  |
| `/src/build.sh` | build script for the project |
| `/src/<project>` | checked out sources for the project;  mounted when run |
| `/out/` | build artifacts should be copied here  |
| `/work/` | used to store intermediate files |
