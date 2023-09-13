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
const yaml = require('./index');

module.exports.fuzz = function(data) {
  const provider = new FuzzedDataProvider(data);
  const loadOptions = generateRandomLoadOptions(provider);
  const dumpOptions = generateRandomDumpOptions(provider);
  const yamlString = provider.consumeRemainingAsString();


  try {
    const parsedYaml = yaml.load(yamlString, loadOptions);
    const _serializedYaml = yaml.dump(parsedYaml, dumpOptions);
  } catch (YAMLException) {
  }
};


function generateRandomLoadOptions(provider) {
  const options = {};
  options.schema = getSchema(provider.consumeIntegralInRange(0, 3));
  options.json = provider.consumeBoolean();
  return options;
}

function generateRandomDumpOptions(provider) {
  const options = {};
  options.indent = provider.consumeIntegralInRange(0, 4096);
  options.skipInvalid = provider.consumeBoolean();
  options.flowLevel = provider.consumeIntegralInRange(-1, 100);
  options.schema = getSchema(provider.consumeIntegralInRange(0, 3));
  options.sortKeys = provider.consumeBoolean();
  options.lineWidth = provider.consumeIntegralInRange(0, 4096);
  options.noRefs = provider.consumeBoolean();
  options.noCompatMode = provider.consumeBoolean();
  options.condenseFlow = provider.consumeBoolean();
  options.forceQuotes = provider.consumeBoolean();
  return options;
}


function getSchema(number) {

  switch (number) {
    case 0:
      options.schema = "DEFAULT_SCHEMA";
      break
    case 1:
      options.schema = "FAILSAFE_SCHEMA";
      break
    case 2:
      options.schema = "JSON_SCHEMA";
      break
    case 3:
      options.schema = "CORE_SCHEMA";
      break
  }
}
