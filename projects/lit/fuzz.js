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
const { LitElement, html } = require('./packages/lit/index');

module.exports.fuzz = function(data) {
  try {
    const provider = new FuzzedDataProvider(data);
    const element = new LitElement();
    const properties = {};
    const numProperties = provider.consumeIntegralInRange(0, 32);
    const template = provider.consumeString(
      provider.consumeIntegralInRange(0, 4096)
    );

    for (let i = 0; i < numProperties; i++) {
      const key = provider.consumeString(32);
      let value;
      switch (provider.consumeIntegralInRange(0, 7)) {
        case 0:
          value = provider.consumeBoolean();
          break;
        case 1:
          value = provider.consumeIntegralInRange(0, 2 ** 48 - 1);
          break;
        case 2:
          value = provider.consumeIntegralInRange(-(2 ** 48 - 1), 0);
          break;
        case 3:
          value = provider.consumeString(
            provider.consumeIntegralInRange(0, 256)
          );
          break;
        case 4:
          value = provider.consumeFloat();
          break;
        case 5:
          value = provider.consumeDouble();
          break;
        case 6:
          const isSigned = provider.consumeBoolean();
          value = provider.consumeBigIntegral(8, isSigned);
          break;
        default:
          value = null;
      }
      properties[key] = value;
    }

    element.render(html`${template}`);
    element.update(properties);

    const attributeName = provider.consumeString(
      provider.consumeIntegralInRange(0, 128)
    );
    const attributeValue = provider.consumeString(
      provider.consumeIntegralInRange(0, 128)
    );
    element.attributeChangedCallback(attributeName, null, attributeValue);
    element.connectedCallback();
    element.disconnectedCallback();
    element.shouldUpdate(properties);

    const propKey = provider.consumeString(
      provider.consumeIntegralInRange(0, 256)
    );
    const attrKey = provider.consumeString(
      provider.consumeIntegralInRange(0, 256)
    );
    const propValue = provider.consumeString(
      provider.consumeIntegralInRange(0, 256)
    );
    const attrValue = provider.consumeString(
      provider.consumeIntegralInRange(0, 256)
    );

    Object.defineProperty(element, propKey, {
      get() {
        return propValue;
      },
      set(value) {
        propValue = value;
      },
    });

    element.setAttribute(attrKey, attrValue);
  } catch (error) {
    if (!ignoredError(error)) throw error;
  }
};

function ignoredError(error) {
  return !!ignored.find((message) => error.message.indexOf(message) !== -1);
}

const ignored = ['Cannot read properties'];

