# Changelog - Base Images Refactoring

## Summary

This changelog documents the refactoring of the base image infrastructure in `infra/base-images` to add support for Ubuntu 24.04 while maintaining compatibility with Ubuntu 20.04. The work was carried out incrementally, following the dependency tree of the images.

## Changes Made

### 1. Multi-version Ubuntu Support

-   **Ubuntu 24.04**: Added full support for building all base images on top of Ubuntu 24.04.
-   **Ubuntu 20.04**: Support maintained and validated in parallel with the new version.

### 2. Dockerfile Structure

-   For each image, specific `Dockerfile`s were created for each Ubuntu version:
    -   `ubuntu_20_04.Dockerfile`
    -   `ubuntu_24_04.Dockerfile`
-   The original and generic `Dockerfile`s were preserved to maintain history and facilitate reference, but they are no longer used directly in the build process.

### 3. Robust Build Process

-   The build process was adjusted to use locally built base images, removing the `--pull` parameter to avoid unnecessary failures.
-   Resource allocation parameters (`--cpuset-cpus` and `--memory`) were standardized to ensure stable builds.

### 4. Documentation and Reports

-   A `BUILD_ANALYSIS_AND_REPORT.md` file was introduced for each image. This file documents:
    -   Dependency analysis.
    -   The action plan for the migration.
    -   The build status for each Ubuntu version.
    -   A conclusion on the results.

## Processed Images

The following is the list of images processed in the order of the dependency tree:

1.  `base-image`
2.  `base-clang`
3.  `base-builder`
4.  `base-builder-go`
5.  `base-builder-javascript`
6.  `base-builder-jvm`
7.  `base-builder-python`
8.  `base-builder-ruby`
9.  `base-builder-rust`
10. `base-builder-swift`
11. `base-builder-fuzzbench`
12. `base-runner`
13. `base-runner-debug`

## Conclusion

The base image infrastructure now robustly and documentedly supports Ubuntu versions 20.04 and 24.04, ensuring the continuity and modernization of the fuzzing environment.