# Security documentation of OSS-Fuzz


## Build and run is treated as trusted data

OSS-Fuzz is a service for continuous fuzzing of open source software. OSS-Fuzz
can also be used as a toolbox to build and run fuzzing harnesses locally, and
OSS-Fuzz provides Docker images and helper utilities to make these tasks easy.

OSS-Fuzz treats all input for building and running of fuzzers as trusted
data. Specifically, OSS-Fuzz does not provide security protection when building
or running fuzzing harnesses. OSS-Fuzz builds fuzzing harnesses inside Docker
images and also runs fuzzing harnesses inside Docker containers. Specifically:

- The Docker images are meant to only run trusted code.
- OSS-Fuzz considers the input to building fuzzing harnesses and running fuzzing
  harnesses as trusted. Only build and run fuzzing harnesses that
  you trust.

Consequently:

- Do not build projects you do not fully trust.
- Do not run fuzzing harnesses for projects you do not trust.

The Docker images/containers are not considered a security boundary in the
OSS-Fuzz threat model.

## Reporting

To report a security issue, please use https://g.co/vulnz.
