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
const tslib = require('./tslib.js');

module.exports.fuzz = function(data) {
  const provider = new FuzzedDataProvider(data);

  try {
    const functionList = [
      '__assign',
      '__rest',
      '__spread',
      '__decorate',
      '__param',
      '__awaiter',
      '__generator',
      '__exportStar',
      '__values',
      '__read',
      '__spreadArrays',
      '__spreadArray',
      '__extends'
    ];

    const functionName = provider.pickValue(functionList);

    let numProperties;
    switch (functionName) {
      case '__assign':

        const target = {};
        const numSources = provider.consumeIntegral(1, false);
        const sources = [];
        for (let i = 0; i < numSources; i++) {
          const source = {};
          numProperties = provider.consumeIntegral(1, false);
          for (let j = 0; j < numProperties; j++) {
            const key = provider.consumeString(10);
            const value = provider.consumeBoolean() ? provider.consumeString(10) : provider.consumeNumber();
            source[key] = value;
          }
          sources.push(source);
        }


        tslib.__assign(target, ...sources);
        break;

      case '__rest':

        const obj = {};
        numProperties = provider.consumeIntegral(1, false);
        for (let i = 0; i < numProperties; i++) {
          const key = provider.consumeString(10);
          const value = provider.consumeBoolean() ? provider.consumeString(10) : provider.consumeNumber();
          obj[key] = value;
        }
        const keys = Object.keys(obj);
        const excludedKeys = keys.sort(() => Math.random() - 0.5).slice(0, provider.consumeIntegral(1, false));


        tslib.__rest(obj, excludedKeys);
        break;

      case '__spread':

        const arr = [];
        const numArrays = provider.consumeIntegral(1, false);
        for (let i = 0; i < numArrays; i++) {
          const subArr = [];
          const numElements = provider.consumeIntegral(1, false);
          for (let j = 0; j < numElements; j++) {
            const element = provider.consumeBoolean() ? provider.consumeString(10) : provider.consumeNumber();
            subArr.push(element);
          }
          arr.push(subArr);
        }


        tslib.__spreadArray([], arr, true);
        break;

      case '__decorate':

        const classConstructor = function() { };
        const numDecorators = provider.consumeIntegral(1, false);
        const decorators = [];
        for (let i = 0; i < numDecorators; i++) {
          const decorator = function() { };
          decorators.push(decorator);
        }


        tslib.__decorate(decorators, classConstructor.prototype, 'methodName', Object.getOwnPropertyDescriptor(classConstructor.prototype, 'methodName'));
        break;

      case '__param':

        const index = provider.consumeIntegral(1, false);
        const decorator = function() { };


        tslib.__param(index, decorator);
        break;

      case '__metadata':

        const key = provider.consumeString(10);
        const value = provider.consumeBoolean() ? provider.consumeString(10) : provider.consumeNumber();
        const target1 = function() { };


        tslib.__metadata(key, value)(target1, 'methodName', 0);
        break;

      case '__awaiter':

        const thisArg = {};
        const _arguments = [];
        const resolve = function() { };
        const reject = function() { };


        tslib.__awaiter(thisArg, _arguments, resolve, reject);
        break;

      case '__generator':

        const obj1 = {};
        const body = function() { };
        const methodName = provider.consumeString(10);


        tslib.__generator(obj1, body, methodName);
        break;

      case '__exportStar':

        const moduleObj = {};
        const exportsObj = {};


        tslib.__exportStar(moduleObj, exportsObj);
        break;

      case '__values':

        const iterable = [];
        const iteratorMethod = function() { };


        tslib.__values(iterable, iteratorMethod);
        break;

      case '__read':

        const iterator = {};
        tslib.__read(iterator, true);

        break;

      case '__spreadArrays':

        const arr1 = [];
        const arr2 = [];
        const arr3 = [];
        const arr4 = [];
        const arr5 = [];


        tslib.__spreadArray([], arr1).concat(tslib.__spreadArray([], arr2), tslib.__spreadArray([], arr3), tslib.__spreadArray([], arr4), tslib.__spreadArray([], arr5));
        break;

      case '__spreadArray':

        const to = [];
        const from = [];
        const condition = function() { };


        tslib.__spreadArray(to, from, condition);
        break;

      case '__extends':

        const derivedCtor = provider.consumeString(10);
        const baseCtor = provider.consumeString(10);


        const proto = {};
        numProperties = provider.consumeIntegral(1, false);
        for (let i = 0; i < numProperties; i++) {
          const key = provider.consumeString(10);
          const value = provider.consumeBoolean() ? provider.consumeString(10) : provider.consumeNumber();
          proto[key] = value;
        }


        tslib.__extends(derivedCtor, baseCtor, proto);
        break;

      default:
        break;
    }

  } catch (error) {
    if (!ignoredError(error)) throw error;
  }
};

function ignoredError(error) {
  return !!ignored.find((message) => error.message.indexOf(message) !== -1);
}

const ignored = [
  "Class extends value"
];
