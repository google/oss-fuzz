# Docker Image Version Changelog: oss-fuzz/base-builder-ruby

## Analysis Summary

The `ubuntu-20-04` and `ubuntu-24-04` images for `oss-fuzz/base-builder-ruby` were successfully built. These images install Ruby and the Ruzzy fuzzer on top of the `base-builder` image. The Dockerfile structure was refactored to support multi-version builds by creating separate Dockerfiles for each Ubuntu version and updating the `FROM` instruction accordingly.

## Build Status

| Image Tag | Dockerfile | Status |
| --- | --- | --- |
| `oss-fuzz/base-builder-ruby:ubuntu-20-04` | `ubuntu-20-04.Dockerfile` | Success |
| `oss-fuzz/base-builder-ruby:ubuntu-24-04` | `ubuntu-24-04.Dockerfile` | Success |

## Package Comparison

### Key Differences (Ubuntu 20.04 vs. Ubuntu 24.04)

The primary difference is the version of Ruby and its dependencies. Both versions install Ruby 3.3.1, but the underlying system libraries and dependencies are different.

## Dockerfile Analysis

The Dockerfiles for both versions have the following key differences:

*   **Base Image:** The `FROM` instruction in each Dockerfile points to the corresponding `oss-fuzz/base-builder` tag (`ubuntu-20-04` or `ubuntu-24-04`).
*   **Ruby Installation:** The `install_ruby.sh` script is used to download and install Ruby.
*   **Ruzzy Installation:** Both versions clone the Ruzzy repository and install it using `gem`.
*   **Refactoring:** The original `Dockerfile` was renamed to `ubuntu-20-04.Dockerfile`, and a new `ubuntu-24-04.Dockerfile` was created to support the multi-version build strategy.
