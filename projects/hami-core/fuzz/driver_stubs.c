/* Copyright 2026 Reza Jelveh
 * SPDX-License-Identifier: Apache-2.0
 */

/* Weak stubs for driver/NVML symbols the TU references but fuzz targets
 * never call. NVML_NO_UNVERSIONED_FUNC_DEFS matches nvml_prefix.h so the
 * plain names match the TU's references. */

#define NVML_NO_UNVERSIONED_FUNC_DEFS
#include <nvml.h>

unsigned int cuda_to_nvml_map(unsigned int cudadev) __attribute__((weak));
unsigned int cuda_to_nvml_map(unsigned int cudadev) { return cudadev; }

int setspec(void) __attribute__((weak));
int setspec(void) { return 0; }

const char* nvmlErrorString(nvmlReturn_t result) __attribute__((weak));
const char* nvmlErrorString(nvmlReturn_t result) { return ""; }

nvmlReturn_t nvmlDeviceGetCount_v2(unsigned int* deviceCount)
    __attribute__((weak));
nvmlReturn_t nvmlDeviceGetCount_v2(unsigned int* deviceCount) {
    *deviceCount = 0;
    return NVML_SUCCESS;
}

nvmlReturn_t nvmlDeviceGetHandleByIndex(unsigned int index,
                                        nvmlDevice_t* device)
    __attribute__((weak));
nvmlReturn_t nvmlDeviceGetHandleByIndex(unsigned int index,
                                        nvmlDevice_t* device) {
    *device = 0;
    return NVML_SUCCESS;
}

nvmlReturn_t nvmlDeviceGetUUID(nvmlDevice_t device, char* uuid,
                               unsigned int length) __attribute__((weak));
nvmlReturn_t nvmlDeviceGetUUID(nvmlDevice_t device, char* uuid,
                               unsigned int length) {
    return NVML_SUCCESS;
}

nvmlReturn_t nvmlDeviceGetComputeRunningProcesses(
    nvmlDevice_t device, unsigned int* infoCount, nvmlProcessInfo_v1_t* infos)
    __attribute__((weak));
nvmlReturn_t nvmlDeviceGetComputeRunningProcesses(
    nvmlDevice_t device, unsigned int* infoCount, nvmlProcessInfo_v1_t* infos) {
    return NVML_SUCCESS;
}
