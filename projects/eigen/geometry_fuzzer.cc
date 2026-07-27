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

#include <fuzzer/FuzzedDataProvider.h>
#include <Eigen/Core>
#include <Eigen/Geometry>

namespace {

template <typename Scalar>
void fuzzGeometry(FuzzedDataProvider* stream) {
  typedef Eigen::Matrix<Scalar, 3, 1> Vector3;
  typedef Eigen::Quaternion<Scalar> Quaternion;
  typedef Eigen::AngleAxis<Scalar> AngleAxis;
  typedef Eigen::Rotation2D<Scalar> Rotation2D;
  typedef Eigen::Transform<Scalar, 3, Eigen::Affine> Transform3;

  Vector3 v1(stream->ConsumeFloatingPoint<Scalar>(),
             stream->ConsumeFloatingPoint<Scalar>(),
             stream->ConsumeFloatingPoint<Scalar>());
  Vector3 v2(stream->ConsumeFloatingPoint<Scalar>(),
             stream->ConsumeFloatingPoint<Scalar>(),
             stream->ConsumeFloatingPoint<Scalar>());

  // Quaternions
  Quaternion q1(stream->ConsumeFloatingPoint<Scalar>(),
                stream->ConsumeFloatingPoint<Scalar>(),
                stream->ConsumeFloatingPoint<Scalar>(),
                stream->ConsumeFloatingPoint<Scalar>());
  q1.normalize();
  Quaternion q2(stream->ConsumeFloatingPoint<Scalar>(),
                stream->ConsumeFloatingPoint<Scalar>(),
                stream->ConsumeFloatingPoint<Scalar>(),
                stream->ConsumeFloatingPoint<Scalar>());
  q2.normalize();

  (void)q1.slerp(stream->ConsumeFloatingPoint<Scalar>(), q2);
  (void)q1.inverse();
  (void)q1.conjugate();
  (void)(q1 * q2);
  (void)(q1 * v1);

  // AngleAxis
  AngleAxis aa1(stream->ConsumeFloatingPoint<Scalar>(), v1.normalized());
  (void)aa1.toRotationMatrix();
  (void)Quaternion(aa1);

  // Transform
  Transform3 t1 = Transform3::Identity();
  t1.translate(v1);
  t1.rotate(q1);
  t1.scale(stream->ConsumeFloatingPoint<Scalar>());
  
  (void)(t1 * v2);
  (void)t1.inverse();

  // Hyperplane
  Eigen::Hyperplane<Scalar, 3> hp(v1.normalized(), stream->ConsumeFloatingPoint<Scalar>());
  (void)hp.absDistance(v2);
  (void)hp.projection(v2);

  // ParametrizedLine
  Eigen::ParametrizedLine<Scalar, 3> line(v1, v2.normalized());
  (void)line.distance(v2);
  (void)line.projection(v2);
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider stream(data, size);

  uint8_t type = stream.ConsumeIntegral<uint8_t>();
  if (type % 2 == 0) {
    fuzzGeometry<float>(&stream);
  } else {
    fuzzGeometry<double>(&stream);
  }

  return 0;
}
