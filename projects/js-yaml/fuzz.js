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
const yaml = require('js-yaml');

module.exports.fuzz = function (data) {
  const provider = new FuzzedDataProvider(data);
  const yamlString = provider.consumeRemainingAsString();

  try {
    const parsedYaml = yaml.load(yamlString);
    const serializedYaml = yaml.dump(parsedYaml);
  } catch (YAMLException) {
  }
};
