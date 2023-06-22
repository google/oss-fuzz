// Copyright 2023 Google LLC
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

const { FuzzedDataProvider } = require('@jazzer.js/core');
const moment = require('./moment');

module.exports.fuzz = (data) => {
  const provider = new FuzzedDataProvider(data);

  const year = provider.consumeIntegralInRange(0, 9999);
  const month = provider.consumeIntegralInRange(0, 11);
  const day = provider.consumeIntegralInRange(1, 31);
  const hour = provider.consumeIntegralInRange(0, 23);
  const minute = provider.consumeIntegralInRange(0, 59);
  const second = provider.consumeIntegralInRange(0, 59);
  const m = moment({ years: year, months: month, date: day, hours: hour, minutes: minute, seconds: second});
  const format = provider.consumeString(1000);

  try {
      m.format(format);
  } catch (error) {
    // Catch expected errors to find more interesting bugs.
  }
};
