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

const { FuzzedDataProvider } = require("@jazzer.js/core");
const { getLogFilter } = require("rollup/getLogFilter");

const LOG_FIELDS = [
  "code",
  "message",
  "id",
  "plugin",
  "hook",
  "pluginCode",
  "binding",
  "url",
  "loc",
];

module.exports.fuzz = function (data) {
  const provider = new FuzzedDataProvider(data);

  const filterCount = provider.consumeIntegralInRange(0, 6);
  const filters = [];
  for (let i = 0; i < filterCount; i++) {
    filters.push(provider.consumeString(provider.consumeIntegralInRange(0, 80)));
  }

  let logFilter;
  try {
    logFilter = getLogFilter(filters);
  } catch (error) {
    if (!isExpectedFilterError(error)) {
      throw error;
    }
    return;
  }

  if (typeof logFilter !== "function") {
    return;
  }

  const log = {};
  const fieldCount = provider.consumeIntegralInRange(0, LOG_FIELDS.length);
  for (let i = 0; i < fieldCount; i++) {
    const field = LOG_FIELDS[i];
    log[field] = provider.consumeString(provider.consumeIntegralInRange(0, 60));
  }

  try {
    logFilter(log);
  } catch (error) {
    if (!isExpectedFilterError(error)) {
      throw error;
    }
  }
};

function isExpectedFilterError(error) {
  if (!error || typeof error.message !== "string") {
    return false;
  }
  const message = error.message.toLowerCase();
  return (
    error.code === "INVALID_LOG_FILTER" ||
    message.includes("invalid filter") ||
    message.includes("log filter")
  );
}
