//
// Copyright 2024 The ANGLE Project Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//

// fuzz_spirv_transform.cc: A libfuzzer fuzzer for SPIR-V transformations in the Vulkan backend.

#include <fuzzer/FuzzedDataProvider.h>
#include <vector>

#include "common/spirv/spirv_types.h"
#include "libANGLE/renderer/vulkan/spv_utils.h"
#include "libANGLE/renderer/vulkan/ShaderInterfaceVariableInfoMap.h"

using namespace rx;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 10) return 0;

    FuzzedDataProvider fuzzedData(data, size);

    SpvTransformOptions options;
    options.shaderType = static_cast<gl::ShaderType>(fuzzedData.ConsumeIntegralInRange<int>(0, static_cast<int>(gl::ShaderType::EnumCount) - 1));
    options.isLastPreFragmentStage = fuzzedData.ConsumeBool();
    options.isTransformFeedbackStage = fuzzedData.ConsumeBool();
    options.isTransformFeedbackEmulated = fuzzedData.ConsumeBool();
    options.isMultisampledFramebufferFetch = fuzzedData.ConsumeBool();
    options.enableSampleShading = fuzzedData.ConsumeBool();
    options.validate = fuzzedData.ConsumeBool();
    options.useSpirvVaryingPrecisionFixer = fuzzedData.ConsumeBool();
    options.removeDepthStencilInput = fuzzedData.ConsumeBool();

    ShaderInterfaceVariableInfoMap variableInfoMap;
    
    // Add some random variable info
    uint32_t numVars = fuzzedData.ConsumeIntegralInRange<uint32_t>(0, 10);
    for (uint32_t i = 0; i < numVars; ++i)
    {
        uint32_t id = fuzzedData.ConsumeIntegralInRange<uint32_t>(1, 100);
        ShaderInterfaceVariableInfo &info = variableInfoMap.add(options.shaderType, id);
        info.descriptorSet = fuzzedData.ConsumeIntegralInRange<uint32_t>(0, 3);
        info.binding = fuzzedData.ConsumeIntegralInRange<uint32_t>(0, 16);
        info.location = fuzzedData.ConsumeIntegralInRange<uint32_t>(0, 16);
        info.component = fuzzedData.ConsumeIntegralInRange<uint32_t>(0, 3);
    }

    // The remaining data is the SPIR-V blob
    std::vector<uint8_t> remainingData = fuzzedData.ConsumeRemainingBytes<uint8_t>();
    if (remainingData.size() % 4 != 0)
    {
        remainingData.resize(remainingData.size() - (remainingData.size() % 4));
    }
    
    if (remainingData.empty()) return 0;

    angle::spirv::Blob initialSpirvBlob;
    for (size_t i = 0; i < remainingData.size(); i += 4)
    {
        uint32_t word;
        memcpy(&word, &remainingData[i], 4);
        initialSpirvBlob.push_back(word);
    }

    angle::spirv::Blob spirvBlobOut;
    // We don't care about the result, just want to see if it crashes.
    SpvTransformSpirvCode(options, variableInfoMap, initialSpirvBlob, &spirvBlobOut);

    return 0;
}
