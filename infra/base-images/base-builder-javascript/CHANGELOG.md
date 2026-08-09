# Docker Image Version Changelog: oss-fuzz/base-builder-javascript

## Analysis Summary

The `ubuntu-20-04` and `ubuntu-24-04` images for `oss-fuzz/base-builder-javascript` were successfully built. These images install Node.js and other JavaScript-related tools on top of the `base-builder` image. The build process for both versions is straightforward and relies on the `install_javascript.sh` script, which is compatible with both base images.

## Build Status

| Image Tag | Dockerfile | Status |
| --- | --- | --- |
| `oss-fuzz/base-builder-javascript:ubuntu-20-04` | `ubuntu-20-04.Dockerfile` | Success |
| `oss-fuzz/base-builder-javascript:ubuntu-24-04` | `ubuntu-24-04.Dockerfile` | Success |

## Package Comparison

### Key Differences (Ubuntu 20.04 vs. Ubuntu 24.04)

The primary difference is the version of Node.js installed, which is Node.js 20.x for both versions, but the underlying dependencies may differ due to the base image.

## Dockerfile Analysis

The Dockerfiles for both versions are very similar and perform the following actions:

*   **Base Image:** The `FROM` instruction in each Dockerfile points to the corresponding `oss-fuzz/base-builder` tag (`ubuntu-20-04` or `ubuntu-24-04`).
*   **Node.js Installation:** The `install_javascript.sh` script is used to add the Node.js repository and install Node.js.
