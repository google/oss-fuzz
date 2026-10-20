# PR Title: dbus-sensors: Add OSS-Fuzz integration and expanded fuzzing harness

## Summary

This PR integrates OpenBMC's [dbus-sensors](https://github.com/openbmc/dbus-sensors) repository into OSS-Fuzz and adds a comprehensive fuzzing harness (`utils_fuzzer`) targeting critical utility, path normalization, threshold parsing, and device management modules.

## Key Changes

- **Build Environment & Toolchain**:
  - Configured `base_os_version: ubuntu-24-04` in `project.yaml` to leverage modern C++23 / Clang 22 toolchains and systemd/boost libraries compatible with OpenBMC dependencies.
  - Set up static builds for `sdbusplus` and lightweight `libphosphor_logging.a` stubs to eliminate dynamic linking dependencies.
- **Fuzzing Harness (`utils_fuzzer.cpp`)**:
  - **`SensorPaths`**: Exercises D-Bus path escaping (`sensor_paths::escapePathForDbus`) and unit path resolution (`sensor_paths::getPathForUnits`).
  - **`Utils`**: Exercises D-Bus interface string generation (`configInterfaceName`), sensor name escaping (`escapeName`), sysfs path splitting (`splitFileName`), variant type loading (`loadVariant`), and label permit set processing (`getPermitSet`).
  - **`Thresholds`**: Exercises threshold configuration parsing (`parseThresholdsFromConfig`) and threshold interface string formatting (`getInterface`).
  - **`DeviceMgmt`**: Exercises I2C sensor name search and matching (`sensorNameFind`) and bus address resolution (`getDeviceBusAddr`).
- **Sanitizer & Static Linking**:
  - Statically linked `libssl.a` and `libcrypto.a` to ensure clean execution under OSS-Fuzz runner containers (`base-runner`).

## Verification & Metrics

- **`build_fuzzers`**: Succeeded without compilation or linker warnings.
- **`check_build`**: Passed bad build checks cleanly under `base-runner:ubuntu-24-04`.
- **Fuzzing Performance (30-second local run)**:
  - **Executions**: 894,507 runs (~29,000 exec/s)
  - **Coverage**: 1,755 instrumentation points, 545 corpus inputs
- **Line Coverage Metrics**:
  - `utils_fuzzer.cpp`: **100%** (76 / 76 lines)
  - `DeviceMgmt.hpp`: **80.0%** (4 / 5 lines)
  - `SensorPaths.cpp`: **43.5%** (10 / 23 lines)
  - `Utils.hpp`: **36.8%** (78 / 212 lines)
  - `Thresholds.cpp`: **15.1%** (75 / 498 lines)
  - `Utils.cpp`: **5.8%** (52 / 902 lines)
  - **Total Project Coverage**: **13.1%** line coverage (309 lines hit), **20.4%** branch coverage (86 branches hit)

TAG=agy
CONV=606aebc8-9e3d-4c97-9ec2-2b91b5415f09
