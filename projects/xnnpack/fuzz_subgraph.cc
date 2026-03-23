// OSS-Fuzz harness for XNNPACK subgraph define/reshape operations.
// Targets missing bounds checks in reduce, slice, and tensor definition APIs.
// Finds: stack/heap overflows from unbounded num_dims/num_axes,
//        division by zero from missing return after error,
//        and assertion-only guards compiled out in release.

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>
#include <xnnpack.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider provider(data, size);

  if (xnn_initialize(nullptr) != xnn_status_success) return 0;

  xnn_subgraph_t subgraph = nullptr;
  if (xnn_create_subgraph(3, 0, &subgraph) != xnn_status_success) return 0;

  // Create input tensor with fuzzed rank (0-8)
  const size_t num_dims = provider.ConsumeIntegralInRange<size_t>(0, 8);
  size_t dims[8];
  for (size_t i = 0; i < num_dims; i++) {
    dims[i] = provider.ConsumeIntegralInRange<size_t>(1, 8);
  }

  uint32_t input_id = 0;
  if (xnn_define_tensor_value(subgraph, xnn_datatype_fp32, num_dims, dims,
                              nullptr, 0, XNN_VALUE_FLAG_EXTERNAL_INPUT,
                              &input_id) != xnn_status_success) {
    xnn_delete_subgraph(subgraph);
    return 0;
  }

  uint32_t output_id = 1;
  if (xnn_define_tensor_value(subgraph, xnn_datatype_fp32, 0, nullptr, nullptr,
                              1, XNN_VALUE_FLAG_EXTERNAL_OUTPUT,
                              &output_id) != xnn_status_success) {
    xnn_delete_subgraph(subgraph);
    return 0;
  }

  // Pick which operation to fuzz
  const int op = provider.ConsumeIntegralInRange<int>(0, 4);

  switch (op) {
    case 0: {
      // Fuzz xnn_define_static_reduce_v2: unbounded num_reduction_axes
      const size_t num_axes = provider.ConsumeIntegralInRange<size_t>(0, 12);
      int64_t axes[12];
      for (size_t i = 0; i < num_axes; i++) {
        axes[i] = provider.ConsumeIntegralInRange<int64_t>(-8, 8);
      }
      const int reduce_op = provider.ConsumeIntegralInRange<int>(0, 6);
      xnn_define_static_reduce_v2(subgraph,
                                  static_cast<xnn_reduce_operator>(reduce_op),
                                  num_axes, axes, input_id, output_id, 0);
      break;
    }
    case 1: {
      // Fuzz xnn_define_static_reduce (v1 wrapper): stack overflow
      const size_t num_axes = provider.ConsumeIntegralInRange<size_t>(0, 12);
      size_t axes[12];
      for (size_t i = 0; i < num_axes; i++) {
        axes[i] = provider.ConsumeIntegralInRange<size_t>(0, 8);
      }
      xnn_define_static_reduce(subgraph, xnn_reduce_mean, num_axes, axes,
                               input_id, output_id, 0);
      break;
    }
    case 2: {
      // Fuzz xnn_define_static_slice_v3: unbounded num_dims
      const size_t slice_dims = provider.ConsumeIntegralInRange<size_t>(0, 12);
      int64_t begins[12], ends[12];
      for (size_t i = 0; i < slice_dims; i++) {
        begins[i] = provider.ConsumeIntegralInRange<int64_t>(0, 4);
        ends[i] = provider.ConsumeIntegralInRange<int64_t>(1, 8);
      }
      xnn_define_static_slice_v3(subgraph, slice_dims, begins, ends, nullptr,
                                 input_id, output_id, 0);
      break;
    }
    case 3: {
      // Fuzz xnn_define_even_split: num_outputs=0 guard is assert-only
      const size_t num_outputs = provider.ConsumeIntegralInRange<size_t>(0, 6);
      uint32_t outputs[6];
      for (size_t i = 0; i < num_outputs; i++) {
        outputs[i] = output_id;
      }
      xnn_define_even_split(subgraph, 0, input_id, num_outputs,
                            num_outputs > 0 ? outputs : nullptr, 0);
      break;
    }
    case 4: {
      // Fuzz blockwise quantized tensor: block_size=0 missing return
      const size_t block_size = provider.ConsumeIntegralInRange<size_t>(0, 4);
      size_t bq_dims[] = {4, 8};
      uint16_t scales[32] = {};
      for (auto& s : scales) s = 0x3C00;  // 1.0 in bf16
      uint8_t tensor_data[16] = {};
      uint32_t bq_id = XNN_INVALID_VALUE_ID;
      xnn_define_blockwise_quantized_tensor_value(
          subgraph, xnn_datatype_qbint4, 0, scales, 2, 0, block_size, bq_dims,
          tensor_data, XNN_INVALID_VALUE_ID, 0, &bq_id);
      break;
    }
  }

  // Try to create runtime to trigger reshape-time bugs
  xnn_runtime_t runtime = nullptr;
  xnn_status status = xnn_create_runtime(subgraph, &runtime);
  if (runtime) xnn_delete_runtime(runtime);

  xnn_delete_subgraph(subgraph);
  return 0;
}
