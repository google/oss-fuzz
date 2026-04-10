// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");

// fuzz_model_load.cc
//
// OSS-Fuzz harness for TensorFlow Lite Micro (tflite-micro).
//
// Targets integer overflow in tensor size calculation functions:
//   - BytesRequiredForTensor()     (memory_helpers.cc)
//   - TfLiteEvalTensorByteLength() (memory_helpers.cc)
//   - ElementCount()               (micro_utils.cc)
//   - RuntimeShape::FlatSize()     (runtime_shape.h)
//
// These functions use a signed 32-bit accumulator to multiply tensor
// dimensions without overflow checks. Since dimensions come from
// untrusted .tflite FlatBuffer input, an attacker can craft shapes
// like [4, 1073741825] where 4 * 1073741825 = 4294967300 overflows
// int32 to 4, causing severe under-allocation followed by heap OOB
// writes during kernel Invoke().
//
// Pipeline exercised (same as run_malicious.cc):
//   GetModel(data) -> MicroInterpreter(model, resolver, arena, size)
//   -> AllocateTensors() [overflow in BytesRequiredForTensor]
//   -> fill inputs -> Invoke() [OOB write in FullyConnected kernel]
//
// NOTE: We intentionally do NOT run flatbuffers::Verifier on the input.
// This matches the real TFLM attack surface — MicroInterpreter does not
// verify the FlatBuffer before processing it. The PoC (run_malicious.cc)
// also skips verification. The bug is that TFLM trusts dimension values
// from the unverified FlatBuffer without overflow checks.

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "tensorflow/lite/micro/micro_interpreter.h"
#include "tensorflow/lite/micro/micro_mutable_op_resolver.h"
#include "tensorflow/lite/schema/schema_generated.h"

// Same arena size as the PoC runner (run_malicious.cc).
constexpr int kArenaSize = 200000;
alignas(16) static uint8_t arena[kArenaSize];

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Reject trivially small inputs (can't be valid FlatBuffers)
  // and overly large inputs (avoid OOM in fuzzer infra)
  if (size < 8 || size > 4 * 1024 * 1024) {
    return 0;
  }

  // Step 1: Parse as TFLite model — NO verification, same as run_malicious.cc
  // This is intentional: TFLM's MicroInterpreter does not verify the
  // FlatBuffer, so neither should the fuzz harness. The attacker controls
  // the .tflite file contents and TFLM trusts them.
  const tflite::Model *model = tflite::GetModel(data);
  if (model == nullptr) {
    return 0;
  }

  // Basic null checks to avoid trivial nullptr crashes in the parser
  if (model->subgraphs() == nullptr || model->subgraphs()->size() == 0) {
    return 0;
  }
  if (model->buffers() == nullptr) {
    return 0;
  }

  // Step 2: Set up op resolver — same 4 core ops as run_malicious.cc
  // plus additional common TFLM ops for broader kernel coverage
  tflite::MicroMutableOpResolver<16> resolver;
  resolver.AddFullyConnected();    // primary target — used in PoC
  resolver.AddDequantize();        // used in PoC runner
  resolver.AddQuantize();          // used in PoC runner
  resolver.AddReshape();           // used in PoC runner
  resolver.AddAdd();
  resolver.AddMul();
  resolver.AddSub();
  resolver.AddRelu();
  resolver.AddRelu6();
  resolver.AddSoftmax();
  resolver.AddLogistic();
  resolver.AddConv2D();
  resolver.AddDepthwiseConv2D();
  resolver.AddMaxPool2D();
  resolver.AddAveragePool2D();
  resolver.AddMean();

  // Step 3: Create interpreter and allocate tensors
  // AllocateTensors() calls BytesRequiredForTensor() for each tensor.
  // Integer overflow: element_count (int32) wraps, causing tiny allocation.
  tflite::MicroInterpreter interp(model, resolver, arena, kArenaSize);

  TfLiteStatus alloc_status = interp.AllocateTensors();
  if (alloc_status != kTfLiteOk) {
    return 0;
  }

  // Step 4: Fill input tensors — same pattern as run_malicious.cc
  // (memset if reasonably sized)
  for (size_t i = 0; i < interp.inputs_size(); ++i) {
    TfLiteTensor *inp = interp.input(i);
    if (inp == nullptr || inp->data.raw == nullptr || inp->bytes == 0) {
      continue;
    }
    if (inp->bytes < (size_t)kArenaSize) {
      for (size_t byte_idx = 0; byte_idx < inp->bytes; ++byte_idx) {
        inp->data.raw[byte_idx] = data[byte_idx % size];
      }
    }
  }

  // Step 5: Invoke — kernel reads actual (non-overflowed) dims for loop
  // bounds and writes past the tiny allocation. ASAN catches this.
  interp.Invoke();

  return 0;
}
