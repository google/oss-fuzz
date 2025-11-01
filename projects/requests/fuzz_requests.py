#!/usr/bin/python3
#
# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

import atheris
import sys

# urllib3 slows down the initial startup and analysis phases of fuzz target runs
# because of how it is imported in requests.compat so it is excluded here.
with atheris.instrument_imports(
    exclude=['urllib3', 'urllib3.util', 'urllib.parse', 'urllib.request']):
  import requests_mock
  import requests
  from requests.auth import HTTPDigestAuth
  from requests.cookies import cookiejar_from_dict, CookieConflictError
  from requests.exceptions import RequestException


def is_expected_error(error_content_list, error_msg):
  for error in error_content_list:
    if error in error_msg:
      return True
  return False


def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH']

  try:
    cookie_jar = cookiejar_from_dict({
        fdp.ConsumeString(10): fdp.ConsumeString(20)
        for _ in range(fdp.ConsumeIntInRange(1, 3))
    })
  except CookieConflictError:
    return -1

  try:
    with requests_mock.Mocker() as global_mock:
      global_mock.request(method=requests_mock.ANY,
                          url=requests_mock.ANY,
                          status_code=fdp.ConsumeIntInRange(0, 599),
                          reason=fdp.ConsumeString(fdp.ConsumeIntInRange(
                              0, 100)),
                          text=fdp.ConsumeString(fdp.ConsumeIntInRange(0, 100)),
                          headers={
                              fdp.ConsumeString(10): fdp.ConsumeString(20)
                              for _ in range(fdp.ConsumeIntInRange(1, 3))
                          },
                          cookies={
                              fdp.ConsumeString(10): fdp.ConsumeString(20)
                              for _ in range(fdp.ConsumeIntInRange(1, 3))
                          })

      r1 = requests.request(
          fdp.PickValueInList(http_methods),
          url=fdp.ConsumeString(fdp.ConsumeIntInRange(0, 100)),
          allow_redirects=fdp.ConsumeBool(),
          auth=HTTPDigestAuth(fdp.ConsumeString(fdp.ConsumeIntInRange(0, 100)),
                              fdp.ConsumeString(fdp.ConsumeIntInRange(0, 100))),
          params=fdp.ConsumeBytes(fdp.ConsumeIntInRange(1, 512)),
          timeout=fdp.ConsumeFloatInRange(0.1, 5.0),
          headers={
              fdp.ConsumeString(10): fdp.ConsumeString(20)
              for _ in range(fdp.ConsumeIntInRange(1, 3))
          },
          cookies=cookie_jar)
      _ = r1.status_code
      _ = r1.reason
      _ = r1.headers
      _ = r1.cookies
      _ = r1.encoding
      _ = r1.text
      r1.close()

      s = requests.Session()
      s.auth = (fdp.ConsumeString(fdp.ConsumeIntInRange(0, 100)),
                fdp.ConsumeString(fdp.ConsumeIntInRange(0, 100)))
      s.headers.update({
          fdp.ConsumeString(10): fdp.ConsumeString(20)
          for _ in range(fdp.ConsumeIntInRange(1, 5))
      })

      proxies = {
          'http': fdp.ConsumeString(fdp.ConsumeIntInRange(0, 100)),
          'https': fdp.ConsumeString(fdp.ConsumeIntInRange(0, 100)),
      }
      s.proxies.update(proxies)

      custom_method = fdp.ConsumeString(fdp.ConsumeIntInRange(0, 20))
      url_with_port = f"'https://'{fdp.ConsumeString(fdp.ConsumeIntInRange(0, 100))}:{fdp.ConsumeIntInRange(0, 10000)}/"
      req = requests.Request(custom_method,
                             url=url_with_port,
                             data=fdp.ConsumeBytes(
                                 fdp.ConsumeIntInRange(1, 1024)))
      prepped_request = req.prepare()

      with requests_mock.Mocker(session=s) as session_mock:
        session_mock.request(method=requests_mock.ANY,
                             url=requests_mock.ANY,
                             status_code=fdp.ConsumeIntInRange(0, 599),
                             content=fdp.ConsumeBytes(
                                 fdp.ConsumeIntInRange(0, sys.maxsize)))
        r2 = s.send(prepped_request)
        _ = r2.content
        r2.close()
  except (RequestException, ValueError) as e:
    expected_error_message_content = ["Invalid IPV4 URL", "Invalid IPV6 URL"]
    if (isinstance(e, RequestException) or (isinstance(e, ValueError)) and
        is_expected_error(expected_error_message_content, str(e))):
      return -1


def main():
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
