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
const _ = require('lodash')

module.exports.fuzz = async function(data) {
  const provider = new FuzzedDataProvider(data)

  try {
    const input = provider.consumeIntegrals(10, 1, true)
    const chunkSize = provider.consumeIntegralInRange(1, input.length)
    _.chunk(input, chunkSize)

    const array = provider.consumeBooleans(10)
    _.compact(array)

    const array1 = provider.consumeIntegrals(5, 1, true)
    const array2 = provider.consumeIntegrals(5, 1, true)
    _.concat(array1, array2)

    const array3 = provider.consumeIntegrals(10, 1, true)
    const n = provider.consumeIntegralInRange(1, array3.length)
    _.drop(array3, n)

    const array4 = provider.consumeIntegrals(10, 1, true)
    const predicate = (value) => value % 2 === 0
    _.filter(array4, predicate)

    const array5 = provider.consumeIntegrals(5, 1, true)
    const array6 = provider.consumeIntegrals(5, 1, true)
    const array7 = provider.consumeIntegrals(5, 1, true)
    const array8 = [array5, array6, array7]
    _.flatten(array8)

    const array9 = provider.consumeIntegrals(10, 1, true)
    const iteratee = (value) => value * 2
    _.map(array9, iteratee)

    const array10 = provider.consumeIntegrals(10, 1, true)
    _.reverse(array10)

    const array11 = provider.consumeIntegrals(10, 1, true)
    const start = provider.consumeIntegralInRange(0, array11.length - 1)
    const end = provider.consumeIntegralInRange(start, array11.length - 1)
    _.slice(array11, start, end)

    const array13 = provider.consumeIntegrals(10, 1, true)
    _.uniq(array13)

    const templateString = provider.consumeString(50)

    const dataObject = generateDataObject(provider)

    _.template(templateString)(dataObject)

    const object1 = generateDataObject(provider)
    const object2 = generateDataObject(provider)
    _.assign(object1, object2)

    const object3 = generateDataObject(provider)
    _.cloneDeep(object3)

    const object4 = generateDataObject(provider)
    const defaults = generateDataObject(provider)
    _.defaults(object4, defaults)

    const array14 = provider.consumeIntegrals(10, 1, true)
    const predicate2 = (value) => value % 2 === 0
    _.find(array14, predicate2)

    const array15 = provider.consumeIntegrals(10, 1, true)
    const iteratee2 = (_value) => {
    }
    _.forEach(array15, iteratee2)

    const array16 = provider.consumeIntegrals(10, 1, true)
    const iteratee3 = (value) => value % 2 === 0
    _.groupBy(array16, iteratee3)

    const object5 = generateDataObject(provider)
    const object6 = generateDataObject(provider)
    _.isEqual(object5, object6)

    const object7 = generateDataObject(provider)
    const source = generateDataObject(provider)
    _.merge(object7, source)

    const object8 = generateDataObject(provider)
    const numStrings = provider.consumeIntegralInRange(1, 5)
    let strings = []
    for (let i = 0; i < numStrings; i++) {
      strings.push(provider.consumeString(10))
    }
    _.omit(object8, strings)

    const object9 = generateDataObject(provider)
    strings = []
    for (let i = 0; i < numStrings; i++) {
      strings.push(provider.consumeString(10))
    }
    _.pick(object9, strings)

    const array17 = provider.consumeIntegrals(10, 1, true)
    const iteratee4 = (accumulator, value) => accumulator + value
    _.reduce(array17, iteratee4)

    const array18 = provider.consumeIntegrals(10, 1, true)
    _.sortBy(array18)

    _.templateSettings.interpolate = /{{([\s\S]+?)}}/g
    _.templateSettings.evaluate = /{%([\s\S]+?)%}/g
    _.templateSettings.escape = /{{-([\s\S]+?)}}/g

    const func = () => {
    }
    const throttled = _.throttle(func, 1000)
    throttled()

    const num = provider.consumeIntegralInRange(1, 10)
    const iteratee5 = (_n) => {
    }
    _.times(num, iteratee5)

    const object10 = generateDataObject(provider)
    const iteratee6 = (accumulator, value, key) => {
      accumulator[key] = value
      return accumulator
    }
    _.transform(object10, iteratee6)

    const array19 = provider.consumeIntegrals(10, 1, true)
    const iteratee7 = (value) => value % 2 === 0
    _.uniqBy(array19, iteratee7)

    const array20 = provider.consumeIntegrals(5, 1, true)
    const array21 = provider.consumeIntegrals(5, 1, true)
    const array22 = [array20, array21]
    _.zip(array22)
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
