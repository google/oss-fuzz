// Copyright 2024 Google LLC
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

#include "Poco/MemoryStream.h"
#include "Poco/Net/EscapeHTMLStream.h"
#include "Poco/Net/HTMLForm.h"
#include "Poco/Net/HTTPCredentials.h"
#include "Poco/Net/HTTPRequest.h"
#include "Poco/Net/HTTPResponse.h"
#include "Poco/Net/OAuth10Credentials.h"
#include "Poco/Net/OAuth20Credentials.h"
#include "Poco/NullStream.h"

using namespace Poco;

template <class F>
void catchExceptions(const F &func) {
  try {
    func();
  } catch (const std::exception &) {
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  NullOutputStream null;

  // HTTPRequest parsing
  catchExceptions([&] {
    MemoryInputStream stream(reinterpret_cast<const char *>(data), size);
    Net::HTTPRequest request;
    request.read(stream);
    request.write(null);
  });

  // HTTPResponse parsing
  catchExceptions([&] {
    MemoryInputStream stream(reinterpret_cast<const char *>(data), size);
    Net::HTTPResponse response;
    response.read(stream);
    response.write(null);
  });

  // HTTPCredentials
  catchExceptions([&] {
    MemoryInputStream stream(reinterpret_cast<const char *>(data), size);
    Net::HTTPResponse response;
    response.read(stream);

    Net::HTTPRequest request(Net::HTTPRequest::HTTP_GET, "/");
    request.setHost(response.get(Net::HTTPRequest::HOST));

    Net::HTTPCredentials creds;
    creds.authenticate(request, response);
    creds.updateAuthInfo(request);
    creds.proxyAuthenticate(request, response);
    creds.updateProxyAuthInfo(request);
  });

  // OAuth10Credentials
  catchExceptions([&] {
    MemoryInputStream stream(reinterpret_cast<const char *>(data), size);
    Net::HTTPRequest request;
    request.read(stream);

    Net::EscapeHTMLOutputStream htmlStream(null);
    Net::HTMLForm form(request, stream);
    form.prepareSubmit(request);
    form.write(htmlStream);

    Net::OAuth10Credentials oauth10(request);
    oauth10.verify(request, URI(request.getURI()), form);
    oauth10.authenticate(request, URI(request.getURI()), form);
  });

  // OAuth20Credentials
  catchExceptions([&] {
    MemoryInputStream stream(reinterpret_cast<const char *>(data), size);
    Net::HTTPRequest request;
    request.read(stream);

    Net::OAuth20Credentials oauth20(request);
    oauth20.authenticate(request);
  });

  return 0;
}
