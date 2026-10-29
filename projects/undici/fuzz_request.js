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
const { MockAgent, request } = require('undici')

const METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']

function sanitizeHeaderName(value) {
  const sanitized = value.toLowerCase().replace(/[^a-z0-9-]/g, '')
  return sanitized.length === 0 ? 'x-fuzz' : sanitized
}

function sanitizeHeaderValue(value) {
  return value.replace(/[\r\n\0]/g, '')
}

function buildHeaders(provider, maxHeaders) {
  const headers = {}
  const count = provider.consumeIntegralInRange(0, maxHeaders)
  for (let i = 0; i < count; i += 1) {
    const name = sanitizeHeaderName(provider.consumeString(provider.consumeIntegralInRange(1, 32)))
    const value = sanitizeHeaderValue(provider.consumeString(provider.consumeIntegralInRange(0, 128)))
    headers[name] = value
  }
  return headers
}

function buildPath(provider) {
  const segmentCount = provider.consumeIntegralInRange(1, 4)
  const segments = []
  for (let i = 0; i < segmentCount; i += 1) {
    const raw = provider.consumeString(provider.consumeIntegralInRange(0, 24))
    const segment = encodeURIComponent(raw || 'fuzz')
    segments.push(segment)
  }
  let path = `/${segments.join('/')}`
  if (provider.consumeBoolean()) {
    const key = encodeURIComponent(provider.consumeString(provider.consumeIntegralInRange(0, 12)) || 'k')
    const value = encodeURIComponent(provider.consumeString(provider.consumeIntegralInRange(0, 24)))
    path += `?${key}=${value}`
  }
  return path
}

module.exports.fuzz = async function (data) {
  const provider = new FuzzedDataProvider(data)
  const method = METHODS[provider.consumeIntegralInRange(0, METHODS.length - 1)]
  const path = buildPath(provider)
  const headers = buildHeaders(provider, 12)

  let body
  if (method !== 'GET' && method !== 'HEAD' && provider.consumeBoolean()) {
    body = provider.consumeString(provider.consumeIntegralInRange(0, 2048))
    if (headers['content-type'] === undefined) {
      headers['content-type'] = 'text/plain'
    }
  }

  const mockAgent = new MockAgent()
  mockAgent.disableNetConnect()
  const mockPool = mockAgent.get('https://example.com')

  const statusCode = provider.consumeIntegralInRange(100, 599)
  const responseBody = provider.consumeString(provider.consumeIntegralInRange(0, 1024))
  mockPool.intercept({ path, method }).reply(statusCode, responseBody, {
    headers: {
      'content-type': 'text/plain'
    }
  })

  try {
    const result = await request(`https://example.com${path}`, {
      method,
      headers,
      body,
      dispatcher: mockAgent
    })
    try {
      await result.body.text()
    } catch (_err) {
      if (result.body && typeof result.body.dump === 'function') {
        await result.body.dump()
      }
    }
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
