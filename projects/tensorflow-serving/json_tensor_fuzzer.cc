// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// OSS-Fuzz harness for the TensorFlow Serving JSON tensor parser.
//
// Targets the three HTTP REST API parsing entry points in json_tensor.cc:
//   - FillClassificationRequestFromJson  (/v1/models/*:classify)
//   - FillRegressionRequestFromJson      (/v1/models/*:regress)
//   - FillPredictRequestFromJson         (/v1/models/*:predict)
//
// These functions process untrusted user-supplied HTTP request bodies and are
// the primary attack surface for the TF Serving REST API. CVE-2025-0649
// (unbounded recursion in GetDenseTensorShape / FillTensorProto) was found in
// this path. This harness ensures continuous regression coverage.

#include <cstddef>
#include <cstdint>
#include <string>

#include "absl/strings/string_view.h"
#include "google/protobuf/map.h"
#include "tensorflow/core/framework/tensor_shape.pb.h"
#include "tensorflow/core/framework/types.pb.h"
#include "tensorflow/core/lib/core/status.h"
#include "tensorflow/core/protobuf/meta_graph.pb.h"
#include "tensorflow_serving/apis/classification.pb.h"
#include "tensorflow_serving/apis/predict.pb.h"
#include "tensorflow_serving/apis/regression.pb.h"
#include "tensorflow_serving/util/json_tensor.h"

namespace {

// Provides a minimal single-input float tensorinfo_map for the predict path.
// Using DT_FLOAT covers the most common numeric tensor type and exercises the
// full GetDenseTensorShape + FillTensorProto recursion path.
tensorflow::Status MockGetTensorInfoMap(
    const std::string& /*signature_name*/,
    google::protobuf::Map<std::string, tensorflow::TensorInfo>* map) {
  tensorflow::TensorInfo info;
  info.set_dtype(tensorflow::DT_FLOAT);
  // Unbounded shape — allows any input shape from the fuzz corpus.
  info.mutable_tensor_shape()->set_unknown_rank(true);
  (*map)["input"] = info;
  return tensorflow::OkStatus();
}

// Same as above but for DT_STRING inputs (exercises the bytes/b64 path).
tensorflow::Status MockGetStringTensorInfoMap(
    const std::string& /*signature_name*/,
    google::protobuf::Map<std::string, tensorflow::TensorInfo>* map) {
  tensorflow::TensorInfo info;
  info.set_dtype(tensorflow::DT_STRING);
  info.mutable_tensor_shape()->set_unknown_rank(true);
  (*map)["input"] = info;
  return tensorflow::OkStatus();
}

// Same as above but for DT_INT64 inputs.
tensorflow::Status MockGetInt64TensorInfoMap(
    const std::string& /*signature_name*/,
    google::protobuf::Map<std::string, tensorflow::TensorInfo>* map) {
  tensorflow::TensorInfo info;
  info.set_dtype(tensorflow::DT_INT64);
  info.mutable_tensor_shape()->set_unknown_rank(true);
  (*map)["input"] = info;
  return tensorflow::OkStatus();
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  const absl::string_view json(reinterpret_cast<const char*>(data), size);

  // --- Classify endpoint ---
  // POST /v1/models/{model}:classify
  // Exercises MakeExampleFromJsonObject -> AddValueToFeature
  {
    tensorflow::serving::ClassificationRequest req;
    (void)tensorflow::serving::FillClassificationRequestFromJson(json, &req);
  }

  // --- Regress endpoint ---
  // POST /v1/models/{model}:regress
  // Same parsing path as classify.
  {
    tensorflow::serving::RegressionRequest req;
    (void)tensorflow::serving::FillRegressionRequestFromJson(json, &req);
  }

  // --- Predict endpoint: float input ---
  // POST /v1/models/{model}:predict
  // Exercises GetDenseTensorShape + FillTensorProto (the CVE-2025-0649 path).
  {
    tensorflow::serving::PredictRequest req;
    tensorflow::serving::JsonPredictRequestFormat format =
        tensorflow::serving::JsonPredictRequestFormat::kInvalid;
    (void)tensorflow::serving::FillPredictRequestFromJson(
        json, MockGetTensorInfoMap, &req, &format);
  }

  // --- Predict endpoint: string/bytes input ---
  // Exercises the base64 decode path (JsonDecodeBase64Object).
  {
    tensorflow::serving::PredictRequest req;
    tensorflow::serving::JsonPredictRequestFormat format =
        tensorflow::serving::JsonPredictRequestFormat::kInvalid;
    (void)tensorflow::serving::FillPredictRequestFromJson(
        json, MockGetStringTensorInfoMap, &req, &format);
  }

  // --- Predict endpoint: int64 input ---
  // Exercises integer parsing and type-checking paths.
  {
    tensorflow::serving::PredictRequest req;
    tensorflow::serving::JsonPredictRequestFormat format =
        tensorflow::serving::JsonPredictRequestFormat::kInvalid;
    (void)tensorflow::serving::FillPredictRequestFromJson(
        json, MockGetInt64TensorInfoMap, &req, &format);
  }

  return 0;
}
