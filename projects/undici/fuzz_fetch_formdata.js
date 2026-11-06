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

const { FuzzedDataProvider } = require('@jazzer.js/core')
const { MockAgent, fetch, FormData } = require('undici')

function sanitizeFieldName(value) {
  const sanitized = value.replace(/[^a-zA-Z0-9_-]/g, '')
  return sanitized.length === 0 ? 'field' : sanitized
}

function sanitizeFieldValue(value) {
  return value.replace(/[\r\n\0]/g, '')
}

module.exports.fuzz = async function (data) {
  const provider = new FuzzedDataProvider(data)
  const form = new FormData()
  const fieldCount = provider.consumeIntegralInRange(0, 8)

  for (let i = 0; i < fieldCount; i += 1) {
    const name = sanitizeFieldName(provider.consumeString(provider.consumeIntegralInRange(1, 24)))
    const value = sanitizeFieldValue(provider.consumeString(provider.consumeIntegralInRange(0, 256)))
    form.append(name, value)
  }

  const mockAgent = new MockAgent()
  mockAgent.disableNetConnect()
  const mockPool = mockAgent.get('https://example.com')

  const statusCode = provider.consumeIntegralInRange(200, 599)
  const responseBody = provider.consumeString(provider.consumeIntegralInRange(0, 512))
  const path = '/fuzz'

  mockPool.intercept({ path, method: 'POST' }).reply(statusCode, responseBody, {
    headers: {
      'content-type': 'text/plain'
    }
  })

  try {
    const response = await fetch(`https://example.com${path}`, {
      method: 'POST',
      body: form,
      dispatcher: mockAgent
    })
    await response.text()
  } catch (_err) {
    // Ignore expected errors from invalid inputs.
  } finally {
    try {
      await mockAgent.close()
    } catch (_err) {
      // Ignore cleanup errors.
    }
  }
}
