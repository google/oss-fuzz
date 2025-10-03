# Docker Image Version Changelog: oss-fuzz/base-builder-ruby

## Analysis Summary

The `ubuntu20` and `ubuntu24` images for `oss-fuzz/base-builder-ruby` were successfully built. These images install Ruby and the Ruzzy fuzzer on top of the `base-builder` image. The Dockerfile structure was refactored to support multi-version builds by creating separate Dockerfiles for each Ubuntu version and updating the `FROM` instruction accordingly.

## Build Status

| Image Tag | Dockerfile | Status |
| --- | --- | --- |
| `oss-fuzz/base-builder-ruby:ubuntu20` | `ubuntu_20_04.Dockerfile` | Success |
| `oss-fuzz/base-builder-ruby:ubuntu24` | `ubuntu_24_04.Dockerfile` | Success |

## Package Comparison

### Key Differences (Ubuntu 20.04 vs. Ubuntu 24.04)

The primary difference is the version of Ruby and its dependencies. Both versions install Ruby 3.3.1, but the underlying system libraries and dependencies are different.

## Dockerfile Analysis

The Dockerfiles for both versions have the following key differences:

*   **Base Image:** The `FROM` instruction in each Dockerfile points to the corresponding `oss-fuzz/base-builder` tag (`ubuntu20` or `ubuntu24`).
*   **Ruby Installation:** The `install_ruby.sh` script is used to download and install Ruby.
*   **Ruzzy Installation:** Both versions clone the Ruzzy repository and install it using `gem`.
*   **Refactoring:** The original `Dockerfile` was renamed to `ubuntu_20_04.Dockerfile`, and a new `ubuntu_24_04.Dockerfile` was created to support the multi-version build strategy.
