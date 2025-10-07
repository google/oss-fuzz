# Base Images

This directory contains the base images used by OSS-Fuzz.

## Building

To build all images, run:

```bash
# run from project root
infra/base-images/all.sh
```

## Dependency Tree

The following diagram shows the dependency tree of the base images.

```mermaid
graph TD
    A[base-image] --> B(base-clang);
    B --> C(base-builder);
    C --> D(base-builder-go);
    C --> E(base-builder-javascript);
    C --> F(base-builder-jvm);
    C --> G(base-builder-python);
    C --> H(base-builder-ruby);
    C --> I(base-builder-rust);
    C --> J(base-builder-swift);
    C --> K(base-builder-fuzzbench);
    A --> L(base-runner);
    B --> L;
    C --> L;
    H --> L;
    L --> M(base-runner-debug);
```