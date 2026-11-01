/*
 * Copyright 2026 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <fuzzer/FuzzedDataProvider.h>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "Utils.hpp"
#include "Thresholds.hpp"
#include "SensorPaths.hpp"
#include "DeviceMgmt.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // 1. Fuzz getDeviceBusAddr
  std::string dev_name = fdp.ConsumeRandomLengthString(128);
  size_t bus = 0;
  size_t addr = 0;
  uint64_t bus64 = 0;
  uint64_t addr64 = 0;
  (void)getDeviceBusAddr(dev_name, bus, addr);
  (void)getDeviceBusAddr(dev_name, bus64, addr64);

  // 2. Fuzz escapePathForDbus
  std::string path_str = fdp.ConsumeRandomLengthString(128);
  (void)sensor_paths::escapePathForDbus(path_str);

  // 3. Fuzz SensorPaths helper
  std::string sensor_type = fdp.ConsumeRandomLengthString(32);
  (void)sensor_paths::getPathForUnits(sensor_type);

  // 4. Fuzz Config Maps & Threshold Parsing
  SensorBaseConfigMap config_map;
  config_map["Direction"] = fdp.ConsumeRandomLengthString(32);
  config_map["Severity"] = fdp.ConsumeIntegral<uint64_t>();
  config_map["Value"] = fdp.ConsumeFloatingPoint<double>();
  config_map["Hysteresis"] = fdp.ConsumeFloatingPoint<double>();
  config_map["Label"] = fdp.ConsumeRandomLengthString(32);
  config_map["Index"] = fdp.ConsumeIntegral<int64_t>();
  config_map["PowerState"] = fdp.ConsumeRandomLengthString(32);
  config_map["PollRate"] = fdp.ConsumeFloatingPoint<float>();

  (void)getPowerState(config_map);
  (void)getPollRate(config_map, 1.0f);

  // 3. Fuzz Utils string & path utilities
  std::string name_str = fdp.ConsumeRandomLengthString(64);
  (void)escapeName(name_str);
  (void)configInterfaceName(name_str);

  std::string file_path_str = fdp.ConsumeRandomLengthString(128);
  (void)splitFileName(file_path_str);

  PowerState p_state = PowerState::always;
  setReadState(name_str, p_state);
  try {
    (void)readingStateGood(p_state);
  } catch (...) {}

  // 4. Fuzz Config Maps & Threshold Parsing
  config_map["MinReading"] = fdp.ConsumeFloatingPoint<double>();
  config_map["MaxReading"] = fdp.ConsumeFloatingPoint<double>();

  std::vector<std::string> labels;
  size_t label_count = fdp.ConsumeIntegralInRange<size_t>(0, 5);
  for (size_t i = 0; i < label_count; ++i) {
    labels.push_back(fdp.ConsumeRandomLengthString(16));
  }
  config_map["Labels"] = labels;

  (void)getPermitSet(config_map);
  (void)getPowerState(config_map);
  (void)getPollRate(config_map, 1.0f);

  std::pair<double, double> limits{0.0, 0.0};
  SensorBaseConfiguration sensor_base_config{"TestSensor", config_map};
  findLimits(limits, &sensor_base_config);

  try {
    (void)loadVariant<double>(config_map, "Value");
  } catch (...) {}
  try {
    (void)loadVariant<uint64_t>(config_map, "Severity");
  } catch (...) {}
  try {
    (void)loadVariant<std::string>(config_map, "Direction");
  } catch (...) {}

  SensorData sensor_data;
  std::string intf_name = "xyz.openbmc_project.Configuration.Thresholds." +
                          fdp.ConsumeRandomLengthString(32);
  sensor_data[intf_name] = config_map;

  std::vector<thresholds::Threshold> threshold_vector;
  std::string match_label = fdp.ConsumeRandomLengthString(32);
  int sensor_index = fdp.ConsumeIntegral<int>();

  (void)thresholds::parseThresholdsFromConfig(sensor_data, threshold_vector,
                                              &match_label, &sensor_index);
  (void)thresholds::parseThresholdsFromConfig(sensor_data, threshold_vector,
                                              nullptr, nullptr);

  // 5. Fuzz thresholds interfaces
  for (int i = 0; i <= static_cast<int>(thresholds::Level::ERROR); ++i) {
    (void)thresholds::getInterface(static_cast<thresholds::Level>(i));
  }

  // 6. Fuzz DeviceMgmt helpers
  std::string full_name = fdp.ConsumeRandomLengthString(32);
  std::string partial_name = fdp.ConsumeRandomLengthString(32);
  (void)sensorNameFind(full_name, partial_name);

  return 0;
}
