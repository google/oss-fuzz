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
require("google-closure-library");
const SafeHtml = goog.require('goog.html.SafeHtml');
const googString = goog.require('goog.string.Const');
const TrustedResourceUrl = goog.require('goog.html.TrustedResourceUrl');
const UncheckedResourceUrl = goog.require('goog.html.UncheckedResourceUrl');

module.exports.fuzz = function(data) {
  const provider = new FuzzedDataProvider(data);

  const html = provider.consumeString(300);
  const shouldWrap = provider.consumeBoolean();
  const tagName = shouldWrap ? provider.consumeString(10) : '';

  let safeHtml;
  try {
    const method = provider.consumeIntegralInRange(1, 6);

    switch (method) {
      case 1:
        safeHtml = SafeHtml.create(tagName, { innerHtml: html });
        break;
      case 2:
        safeHtml = SafeHtml.fromConstant(googString.from(html));
        break;
      case 3:
        safeHtml = SafeHtml.fromTrustedResourceUrl(TrustedResourceUrl.fromConstant(googString.from(html)));
        break;
      case 4:
        safeHtml = SafeHtml.fromUntrustedResourceUrl(UncheckedResourceUrl.fromConstant(googString.from(html)));
        break;
      case 5:
        safeHtml = SafeHtml.unwrap(SafeHtml.create(tagName, { innerHtml: html }));
        break;
      case 6:
        safeHtml = SafeHtml.concat(SafeHtml.create(tagName, { innerHtml: html }), SafeHtml.EMPTY);
        break;
    }

    const htmlString = SafeHtml.unwrap(safeHtml);
    const isEmpty = provider.consumeBoolean();
    const emptySafeHtml = isEmpty ? SafeHtml.EMPTY : safeHtml;
    const concatenatedSafeHtml = SafeHtml.concat(safeHtml, emptySafeHtml);
    const isTrusted = provider.consumeBoolean();
    const trustedSafeHtml = isTrusted ? SafeHtml.htmlEscape(htmlString) : concatenatedSafeHtml;
    SafeHtml.unwrap(trustedSafeHtml);
  } catch (error) {
    if (!ignoredError(error)) throw error;
  }
};

function ignoredError(error) {
  return !!ignored.find((message) => error.message.indexOf(message) !== -1);
}

const ignored = [
  "Cannot read properties of"
];
