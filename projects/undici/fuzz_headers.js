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
const { Headers, Request, Response } = require('undici')

const METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']

function sanitizeHeaderName(value) {
  const sanitized = value.toLowerCase().replace(/[^a-z0-9-]/g, '')
  return sanitized.length === 0 ? 'x-fuzz' : sanitized
}

function sanitizeHeaderValue(value) {
  return value.replace(/[\r\n\0]/g, '')
}

function consumeHeaderPairs(provider, maxPairs) {
  const pairs = []
  const count = provider.consumeIntegralInRange(0, maxPairs)
  for (let i = 0; i < count; i += 1) {
    const nameSize = provider.consumeIntegralInRange(1, 40)
    const valueSize = provider.consumeIntegralInRange(0, 128)
    const name = sanitizeHeaderName(provider.consumeString(nameSize))
    const value = sanitizeHeaderValue(provider.consumeString(valueSize))
    pairs.push([name, value])
  }
  return pairs
}

function consumePath(provider) {
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

module.exports.fuzz = function (data) {
  const provider = new FuzzedDataProvider(data)
  const headerPairs = consumeHeaderPairs(provider, 16)

  let headers
  try {
    headers = new Headers(headerPairs)
  } catch (_err) {
    return
  }

  const mutationCount = provider.consumeIntegralInRange(0, 8)
  for (let i = 0; i < mutationCount; i += 1) {
    const name = sanitizeHeaderName(provider.consumeString(provider.consumeIntegralInRange(1, 32)))
    const value = sanitizeHeaderValue(provider.consumeString(provider.consumeIntegralInRange(0, 64)))
    const op = provider.consumeIntegralInRange(0, 2)
    try {
      if (op === 0) {
        headers.append(name, value)
      } else if (op === 1) {
        headers.set(name, value)
      } else {
        headers.delete(name)
      }
    } catch (_err) {
      // Ignore validation errors to keep fuzzing.
    }
  }

  const url = `https://example.com${consumePath(provider)}`
  const method = METHODS[provider.consumeIntegralInRange(0, METHODS.length - 1)]
  try {
    const req = new Request(url, { method, headers })
    req.headers.get('content-type')
    for (const _entry of req.headers.entries()) {
      // Iteration exercises header normalization paths.
    }
  } catch (_err) {
    // Ignore request validation errors.
  }

  try {
    const body = provider.consumeString(provider.consumeIntegralInRange(0, 1024))
    const res = new Response(body, { headers })
    res.headers.get('content-type')
    res.headers.forEach(() => {})
  } catch (_err) {
    // Ignore response validation errors.
  }
}
