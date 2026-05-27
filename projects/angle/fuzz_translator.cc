// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

// fuzz_translator.cc: Improved libfuzzer fuzzer for the shader translator.

#ifdef UNSAFE_BUFFERS_BUILD
#    pragma allow_unsafe_buffers
#endif

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <unordered_map>
#include <vector>

#include "angle_gl.h"
#include "anglebase/no_destructor.h"
#include "common/hash_containers.h"
#include "compiler/translator/Compiler.h"
#include "compiler/translator/util.h"

using namespace sh;

namespace
{
struct TranslatorCacheKey
{
    bool operator==(const TranslatorCacheKey &other) const
    {
        return type == other.type && spec == other.spec && output == other.output;
    }

    uint32_t type   = 0;
    uint32_t spec   = 0;
    uint32_t output = 0;
};
}  // anonymous namespace

namespace std
{

template <>
struct hash<TranslatorCacheKey>
{
    std::size_t operator()(const TranslatorCacheKey &k) const
    {
        return (hash<uint32_t>()(k.type) << 1) ^ (hash<uint32_t>()(k.spec) >> 1) ^
               hash<uint32_t>()(k.output);
    }
};
}  // namespace std

struct TCompilerDeleter
{
    void operator()(TCompiler *compiler) const { DeleteCompiler(compiler); }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ShaderDumpHeader header{};
    if (size <= sizeof(header))
    {
        return 0;
    }

    // Make sure the rest of data will be a valid C string so that we don't have to copy it.
    if (data[size - 1] != 0)
    {
        return 0;
    }

    memcpy(&header, data, sizeof(header));
    ShCompileOptions options{};
    
    // Safety check for offsetof and sizes to avoid buffer overflow if ShCompileOptions changes.
    size_t basicSize = offsetof(ShCompileOptions, metal);
    if (basicSize > sizeof(header.basicCompileOptions)) basicSize = sizeof(header.basicCompileOptions);
    memcpy(&options, &header.basicCompileOptions, basicSize);
    
    memcpy(&options.metal, &header.metalCompileOptions, std::min(sizeof(options.metal), sizeof(header.metalCompileOptions)));
    memcpy(&options.pls, &header.plsCompileOptions, std::min(sizeof(options.pls), sizeof(header.plsCompileOptions)));
    
    size -= sizeof(header);
    data += sizeof(header);
    uint32_t type = header.type;
    uint32_t spec = header.spec;

    // Supported shader types
    if (type != GL_FRAGMENT_SHADER && type != GL_VERTEX_SHADER &&
        type != GL_COMPUTE_SHADER && type != GL_GEOMETRY_SHADER &&
        type != GL_TESS_CONTROL_SHADER && type != GL_TESS_EVALUATION_SHADER)
    {
        return 0;
    }

    // Supported specs
    if (spec > SH_GLES3_2_SPEC)
    {
        return 0;
    }

    ShShaderOutput shaderOutput = static_cast<ShShaderOutput>(header.output);

    // Validation of output format
    switch (shaderOutput)
    {
        case SH_ESSL_OUTPUT:
        case SH_GLSL_150_CORE_OUTPUT:
        case SH_GLSL_330_CORE_OUTPUT:
        case SH_GLSL_400_CORE_OUTPUT:
        case SH_GLSL_410_CORE_OUTPUT:
        case SH_GLSL_420_CORE_OUTPUT:
        case SH_GLSL_430_CORE_OUTPUT:
        case SH_GLSL_440_CORE_OUTPUT:
        case SH_GLSL_450_CORE_OUTPUT:
        case SH_SPIRV_VULKAN_OUTPUT:
        case SH_HLSL_3_0_OUTPUT:
        case SH_HLSL_4_1_OUTPUT:
        case SH_MSL_METAL_OUTPUT:
        case SH_WGSL_OUTPUT:
            break;
        default:
            return 0;
    }

    bool hasUnsupportedOptions = false;

    const bool hasMacGLSLOptions = options.addAndTrueToLoopCondition ||
                                   options.unfoldShortCircuit || options.rewriteRowMajorMatrices;

    if (!IsOutputGLSL(shaderOutput) && !IsOutputESSL(shaderOutput))
    {
        hasUnsupportedOptions =
            hasUnsupportedOptions || options.emulateAtan2FloatFunction || options.clampFragDepth ||
            options.regenerateStructNames || options.rewriteRepeatedAssignToSwizzled ||
            options.useUnusedStandardSharedBlocks || options.selectViewInNvGLSLVertexShader;

        hasUnsupportedOptions = hasUnsupportedOptions || hasMacGLSLOptions;
    }
    else
    {
#if !defined(ANGLE_PLATFORM_APPLE)
        hasUnsupportedOptions = hasUnsupportedOptions || hasMacGLSLOptions;
#endif
    }
    if (!IsOutputESSL(shaderOutput))
    {
        hasUnsupportedOptions = hasUnsupportedOptions || options.skipAllValidationAndTransforms;
    }
    if (!IsOutputSPIRV(shaderOutput))
    {
        hasUnsupportedOptions = hasUnsupportedOptions || options.addVulkanXfbEmulationSupportCode ||
                                options.roundOutputAfterDithering ||
                                options.addAdvancedBlendEquationsEmulation;
    }
    if (!IsOutputHLSL(shaderOutput))
    {
        hasUnsupportedOptions = hasUnsupportedOptions ||
                                options.expandSelectHLSLIntegerPowExpressions ||
                                options.allowTranslateUniformBlockToStructuredBuffer ||
                                options.rewriteIntegerUnaryMinusOperator;
    }
    if (!IsOutputMSL(shaderOutput))
    {
        hasUnsupportedOptions = hasUnsupportedOptions || options.ensureLoopForwardProgress;
    }

    // If there are any options not supported with this output, don't attempt to run the translator.
    if (hasUnsupportedOptions)
    {
        return 0;
    }

    // Make sure the rest of the options are in a valid range.
    options.pls.fragmentSyncType = static_cast<ShFragmentSynchronizationType>(
        static_cast<uint32_t>(options.pls.fragmentSyncType) %
        static_cast<uint32_t>(ShFragmentSynchronizationType::InvalidEnum));

    // Force enable options that are required by the output generators.
    if (IsOutputSPIRV(shaderOutput))
    {
        options.removeInactiveVariables = true;
        options.retainInactiveFragmentOutputs = false;
    }
    if (IsOutputMSL(shaderOutput))
    {
        options.removeInactiveVariables = true;
        options.retainInactiveFragmentOutputs = true;
    }

    if (!sh::Initialize())
    {
        return 0;
    }

    TranslatorCacheKey key;
    key.type   = type;
    key.spec   = spec;
    key.output = shaderOutput;

    using UniqueTCompiler = std::unique_ptr<TCompiler, TCompilerDeleter>;
    static angle::base::NoDestructor<angle::HashMap<TranslatorCacheKey, UniqueTCompiler>>
        translators;

    if (translators->find(key) == translators->end())
    {
        UniqueTCompiler translator(
            ConstructCompiler(type, static_cast<ShShaderSpec>(spec), shaderOutput));

        if (translator == nullptr)
        {
            return 0;
        }

        ShBuiltInResources resources;
        sh::InitBuiltInResources(&resources);

        // Enable all the extensions to have more coverage
        resources.OES_standard_derivatives        = 1;
        resources.OES_EGL_image_external          = 1;
        resources.OES_EGL_image_external_essl3    = 1;
        resources.NV_EGL_stream_consumer_external = 1;
        resources.ARB_texture_rectangle           = 1;
        resources.EXT_blend_func_extended         = 1;
        resources.EXT_conservative_depth          = 1;
        resources.EXT_draw_buffers                = 1;
        resources.EXT_frag_depth                  = 1;
        resources.EXT_shader_texture_lod          = 1;
        resources.EXT_shader_framebuffer_fetch    = 1;
        resources.ARM_shader_framebuffer_fetch    = 1;
        resources.ARM_shader_framebuffer_fetch_depth_stencil = 1;
        resources.EXT_YUV_target                  = 1;
        resources.APPLE_clip_distance             = 1;
        resources.MaxDualSourceDrawBuffers        = 1;
        resources.EXT_gpu_shader5                 = 1;
        resources.MaxClipDistances                = 1;
        resources.EXT_shadow_samplers             = 1;
        resources.EXT_clip_cull_distance          = 1;
        resources.ANGLE_clip_cull_distance        = 1;
        resources.EXT_primitive_bounding_box      = 1;
        resources.OES_primitive_bounding_box      = 1;
        resources.OES_texture_3D                  = 1;
        resources.OES_texture_storage_multisample_2d_array = 1;
        resources.OES_shader_io_blocks            = 1;
        resources.EXT_shader_io_blocks            = 1;
        resources.OES_tessellation_shader         = 1;
        resources.EXT_tessellation_shader         = 1;
        resources.EXT_geometry_shader             = 1;
        resources.OES_geometry_shader             = 1;
        resources.OES_gpu_shader5                 = 1;
        resources.NV_shader_noperspective_interpolation = 1;

        if (!translator->Init(resources))
        {
            return 0;
        }

        (*translators)[key] = std::move(translator);
    }

    auto &translator = (*translators)[key];

    // Enable options that any security-sensitive application should enable
    options.limitExpressionComplexity = true;
    options.limitCallStackDepth                     = true;
    options.rejectWebglShadersWithLargeVariables    = true;
    options.rejectWebglShadersWithUndefinedBehavior = true;
    
    const char *shaderStrings[]       = {reinterpret_cast<const char *>(data)};

    translator->compile(shaderStrings, options);

    return 0;
}
