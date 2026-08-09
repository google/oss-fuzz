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

const { FuzzedDataProvider } = require('@jazzer.js/core')
const lodash = require('lodash')

var abort = 0;

module.exports.fuzz = async function(data) {
  lodash.templateSettings.interpolate = /{{([\s\S]+?)}}/g
  lodash.templateSettings.evaluate = /{%([\s\S]+?)%}/g
  lodash.templateSettings.escape = /{{-([\s\S]+?)}}/g
  const provider = new FuzzedDataProvider(data)
  const randomCase = provider.consumeIntegralInRange(1, 28);

  try {
    switch (randomCase) {
      case 1:
        const input = provider.consumeIntegrals(10, 1, true)
        const chunkSize = provider.consumeIntegralInRange(1, input.length)
        lodash.chunk(input, chunkSize)
        break;
      case 2:
        const array = provider.consumeBooleans(10)
        lodash.compact(array)
        break;
      case 3:
        const array1 = provider.consumeIntegrals(5, 1, true)
        const array2 = provider.consumeIntegrals(5, 1, true)
        lodash.concat(array1, array2)
        break;
      case 4:
        const array3 = provider.consumeIntegrals(10, 1, true)
        const n = provider.consumeIntegralInRange(1, array3.length)
        lodash.drop(array3, n)
        break;
      case 5:
        const array4 = provider.consumeIntegrals(10, 1, true)
        const predicate = (value) => value % 2 === 0
        lodash.filter(array4, predicate)
        break;
      case 6:
        const array5 = provider.consumeIntegrals(5, 1, true)
        const array6 = provider.consumeIntegrals(5, 1, true)
        const array7 = provider.consumeIntegrals(5, 1, true)
        const array8 = [array5, array6, array7]
        lodash.flatten(array8)
        break;
      case 7:
        const array9 = provider.consumeIntegrals(10, 1, true)
        const iteratee = (value) => value * 2
        lodash.map(array9, iteratee)
        break;
      case 8:
        const array10 = provider.consumeIntegrals(10, 1, true)
        lodash.reverse(array10)
        break;
      case 9:
        const array11 = provider.consumeIntegrals(10, 1, true)
        const start = provider.consumeIntegralInRange(0, array11.length - 1)
        const end = provider.consumeIntegralInRange(start, array11.length - 1)
        lodash.slice(array11, start, end)
        break;
      case 10:
        const array13 = provider.consumeIntegrals(10, 1, true)
        lodash.uniq(array13)
        break;
      case 11:
        const templateString = provider.consumeString(provider.consumeIntegralInRange(1, 4096))
        const dataObject = generateDataObject(provider)
        lodash.template(templateString)(dataObject)
        break;
      case 12:
        const object1 = generateDataObject(provider)
        const object2 = generateDataObject(provider)
        lodash.assign(object1, object2)
        break;
      case 13:
        const object3 = generateDataObject(provider)
        lodash.cloneDeep(object3)
        break;
      case 14:
        const object4 = generateDataObject(provider)
        const defaults = generateDataObject(provider)
        lodash.defaults(object4, defaults)
        break;
      case 15:
        const array14 = provider.consumeIntegrals(10, 1, true)
        const predicate2 = (value) => value % 2 === 0
        lodash.find(array14, predicate2)
        break;
      case 16:
        const array15 = provider.consumeIntegrals(10, 1, true)
        const iteratee2 = (_value) => {
        }
        lodash.forEach(array15, iteratee2)
        break;
      case 17:
        const array16 = provider.consumeIntegrals(10, 1, true)
        const iteratee3 = (value) => value % 2 === 0
        lodash.groupBy(array16, iteratee3)
        break;
      case 18:
        const object5 = generateDataObject(provider)
        const object6 = generateDataObject(provider)
        lodash.isEqual(object5, object6)
        break;
      case 19:
        const object7 = generateDataObject(provider)
        const source = generateDataObject(provider)
        lodash.merge(object7, source)
        break;
      case 20:
        const object8 = generateDataObject(provider)
        var numStrings = provider.consumeIntegralInRange(1, 5)
        var strings = []
        for (let i = 0; i < numStrings; i++) {
          strings.push(provider.consumeString(10))
        }
        lodash.omit(object8, strings)
        break;
      case 21:
        const object9 = generateDataObject(provider)
        strings = []
        numStrings = provider.consumeIntegralInRange(1, 5)
        for (let i = 0; i < numStrings; i++) {
          strings.push(provider.consumeString(10))
        }
        lodash.pick(object9, strings)
        break;
      case 22:
        const array17 = provider.consumeIntegrals(10, 1, true)
        const iteratee4 = (accumulator, value) => accumulator + value
        lodash.reduce(array17, iteratee4)
        break;
      case 23:
        const array18 = provider.consumeIntegrals(10, 1, true)
        lodash.sortBy(array18)
        break;
      case 24:
        const func = () => {
        }
        const throttled = lodash.throttle(func, 1000)
        throttled()
        break;
      case 25:
        const num = provider.consumeIntegralInRange(1, 10)
        const iteratee5 = (_n) => {
        }
        lodash.times(num, iteratee5)
        break;
      case 26:
        const object10 = generateDataObject(provider)
        const iteratee6 = (accumulator, value, key) => {
          accumulator[key] = value
          return accumulator
        }
        lodash.transform(object10, iteratee6)
        break;
      case 27:
        const array19 = provider.consumeIntegrals(10, 1, true)
        const iteratee7 = (value) => value % 2 === 0
        lodash.uniqBy(array19, iteratee7)
        break;
      case 28:
        const array20 = provider.consumeIntegrals(5, 1, true)
        const array21 = provider.consumeIntegrals(5, 1, true)
        const array22 = [array20, array21]
        lodash.zip(array22)
        break;
    }

  } catch (error) {
    if (!ignoredError(error)) {
      throw error
    }
  }
}

function ignoredError(error) {
  return !!ignored.find((message) => error.message.indexOf(message) !== -1)
}

const ignored = [
  'min must be less than or equal to max',
  'Unexpected token',
  'is not defined',
  'Invalid or Unexpected'
]

function generateDataObject(provider) {
  const dataObject = {}

  const numProperties = provider.consumeIntegralInRange(1, 10)
  for (let i = 0; i < numProperties; i++) {
    const propertyName = provider.consumeString(10)
    const propertyValue = generatePropertyValue(provider)

    dataObject[propertyName] = propertyValue
  }

  return dataObject
}

function generatePropertyValue(provider) {
  const valueType = provider.consumeIntegralInRange(0, 3)
  abort += 1
  if (abort > 4096) {
    return
  }

  switch (valueType) {
    case 0:
      return provider.consumeString(20)
    case 1:
      return provider.consumeNumber()
    case 2:
      return generateDataObject(provider)
    case 3:
      const numValues = provider.consumeIntegralInRange(1, 5)
      const values = []
      for (let i = 0; i < numValues; i++) {
        values.push(generatePropertyValue(provider))
      }
      return values
  }
}
