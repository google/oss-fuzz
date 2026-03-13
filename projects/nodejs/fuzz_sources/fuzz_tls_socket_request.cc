// Copyright 2025 Google LLC
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

#include <cstdint>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>

#include "fuzz_common.h"
#include "fuzz_js_format.h"

// Static header (existing PEMs + setup; kept intact)
static constexpr std::string_view kHeader = R"(const tls = require('tls');
const https = require('https');
const { setEnvironmentData } = require('worker_threads');
const { send } = require('process');

// Self-signed key/cert (same as your original)
const key = `-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIDKfHHbiJMdu2STyHL11fWC7psMY19/gUNpsUpkwgGACoAoGCCqGSM49
AwEHoUQDQgAEItqm+pYj3Ca8bi5mBs+H8xSMxuW2JNn4I+kw3aREsetLk8pn3o81
PWBiTdSZrGBGQSy+UAlQvYeE6Z/QXQk8aw==
-----END EC PRIVATE KEY-----`;

const cert = `-----BEGIN CERTIFICATE-----
MIIBhjCCASsCFDJU1tCo88NYU//pE+DQKO9hUDsFMAoGCCqGSM49BAMCMEUxCzAJ
BgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5l
dCBXaWRnaXRzIFB0eSBMdGQwHhcNMjAwOTIyMDg1NDU5WhcNNDgwMjA3MDg1NDU5
WjBFMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwY
SW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD
QgAEItqm+pYj3Ca8bi5mBs+H8xSMxuW2JNn4I+kw3aREsetLk8pn3o81PWBiTdSZ
rGBGQSy+UAlQvYeE6Z/QXQk8azAKBggqhkjOPQQDAgNJADBGAiEA7Bdn4F87KqIe
Y/ABy/XIXXpFUb2nyv3zV7POQi2lPcECIQC3UWLmfiedpiIKsf9YRIyO0uEood7+
glj2R1NNr1X68w==
-----END CERTIFICATE-----`;

const options = { key, cert };

let srv;
let socket;
let receivedResponse = 0;

async function send_requests() {
  socket = tls.connect(4444, 'localhost', { rejectUnauthorized: false }, () => {
    const httpRequest = `GET / HTTP/1.1\r\nHost: localhost\r\nConnection: Keep-alive\r\n\r\n`;
    socket.write(httpRequest);
)";

// Template for a single POST using a precomputed body Buffer
static constexpr std::string_view kPostTemplate = R"(
    const body = Buffer.from({0}, 'latin1');
    const postRequest = `POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: ${body.length}\r\n\r\n${body.toString('latin1')}`;
    socket.write(postRequest);
)";

static constexpr std::string_view kFooter = R"(
  });

  socket.on('data', (data) => {
    receivedResponse++;
    if (receivedResponse === 6) {
      socket.end();
    }
  });

  socket.on('end', () => {
    srv.close(() => {});
  });
}

function run_server() {
  srv = https.createServer(options, function (req, res) {
    let chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('ok');
    });
  }).listen(4444);
}

run_server();
send_requests();
)";

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider prov(data, size);
  std::string b1 = prov.ConsumeRandomLengthString();
  std::string b2 = prov.ConsumeRandomLengthString();
  std::string b3 = prov.ConsumeRandomLengthString();

  // Build the whole script: header + 3 posts + footer
  std::string js = std::string(kHeader);
  js += FormatJs(kPostTemplate, ToSingleQuotedJsLiteral(b1));
  js += FormatJs(kPostTemplate, ToSingleQuotedJsLiteral(b2));
  js += FormatJs(kPostTemplate, ToSingleQuotedJsLiteral(b3));
  js += std::string(kFooter);

  fuzz::IsolateScope iso;
  if (!iso.ok()) return 0;

  // Give async networking a few ticks.
  fuzz::EnvRunOptions opts;
  opts.max_pumps = 8;
  fuzz::RunEnvString(iso.isolate(), js.c_str(), opts);
  return 0;
}
