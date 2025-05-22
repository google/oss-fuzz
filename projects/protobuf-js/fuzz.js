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
const ProtoBuf = require('./src/index');
const fs = require('fs');

module.exports.fuzz = function(data) {
  try {
    const provider = new FuzzedDataProvider(data);
    if (provider._remainingBytes < 512) { return; }
    const root = new ProtoBuf.Root();
    const filePath = "fuzz.proto";
    fs.writeFileSync(filePath, Buffer.from(provider.consumeBytes(provider.consumeIntegralInRange(1, 512))));

    // Load the protobuf schema from the temporary file
    root.loadSync(filePath);

    fuzzLoadSync(root, provider);
    fuzzDefine(root, provider);
    fuzzLookupType(root, provider);
    fuzzEncode(root, provider);
    fuzzDecode(root, provider);

    fs.unlinkSync(filePath);
  } catch (error) {
    if (!ignoredError(error)) throw error;
  }
};

function ignoredError(error) {
  return !!ignored.find((message) => error.message.indexOf(message) !== -1);
}

const ignored = [
  "illegal",
  "Unexpected",
  "The value of",
  "must be",
  "duplicate"
];

// Fuzz the Root#loadSync method
function fuzzLoadSync(root, provider) {
  const filePath = provider.consumeString();
  root.loadSync(filePath);
}

// Fuzz the Root#define method
function fuzzDefine(root, provider) {
  const length = provider.consumeIntegralInRange(1, 64);
  const typeName = provider.consumeString(length);
  const definition = provider.consumeString(provider.consumeIntegralInRange(1, 64));
  root.define(typeName, definition);
}

// Fuzz the Root#lookupType method
function fuzzLookupType(root, provider) {
  const typeName = provider.consumeString(provider.consumeIntegralInRange(1, 64));
  root.lookupType(typeName);
}

// Fuzz the Message#encode method
function fuzzEncode(root, provider) {
  const typeName = provider.consumeString();
  const message = root.create(typeName);

  // Construct the input for the message instance manually
  const input = constructInputForEncode(message.$type, provider);
  message.set(input);

  message.encode();
}

// Construct the input for the message instance manually
function constructInputForEncode(type, provider) {
  const input = {};

  for (const field of type.fieldsArray) {
    const fieldName = field.name;
    const fieldType = field.resolvedType;

    if (fieldType && fieldType instanceof ProtoBuf.Type && !field.repeated) {
      // Recursively construct input for nested message types
      const nestedInput = constructInputForEncode(fieldType, provider);
      input[fieldName] = nestedInput;
    } else {
      // Consume a value from the provider for non-nested fields
      const value = consumeValueForField(field, provider);
      input[fieldName] = value;
    }
  }

  return input;
}

// Consume a value from the provider for non-nested fields
function consumeValueForField(field, provider) {
  switch (field.type) {
    case "double":
    case "float":
      return provider.consumeFloat();
    case "int32":
    case "uint32":
    case "sint32":
    case "fixed32":
    case "sfixed32":
      return provider.consumeIntegral(provider.consumeIntegralInRange(0, 4), provider.consumeBool());
    case "int64":
    case "uint64":
    case "sint64":
    case "fixed64":
    case "sfixed64":
      return provider.consumeBigIntegral(provider.consumeIntegralInRange(0, 4), provider.consumeBool());
    case "bool":
      return provider.consumeBool();
    case "string":
      return provider.consumeString(provider.consumeIntegralInRange(0, 64));
    case "bytes":
      return provider.consumeBytes(provider.consumeIntegralInRange(0, 64));
    default:
      return null;
  }
}

// Fuzz the Message#decode method
function fuzzDecode(root, provider) {
  const typeName = provider.consumeString(provider.consumeIntegralInRange(0, 64));
  const buffer = provider.consumeRemainingAsBytes();
  root.lookupType(typeName).decode(buffer);
}

