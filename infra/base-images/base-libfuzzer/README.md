# base-libfuzzer
================

*Abstract* base image for all libfuzzer builders.

Supported commands:

* `docker run -ti <image_name> [compile]` - compiles everything. Expects /src/ paths
  to be mounted.
* `docker run -ti <image_name> checkout` - checks sources out automatically 
  and compiles them.
* `docker run -ti <image_name> /bin/bash` - drop into shell. Run `compile` script
  to start build. 