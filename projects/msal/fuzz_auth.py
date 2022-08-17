#!/usr/bin/python3
# Copyright 2022 Google LLC
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
import atheris
import sys
import requests
with atheris.instrument_imports():
    from msal import PublicClientApplication
    from msal.application import extract_certs
    from msal.authority import AuthorityBuilder


# FuzzHttpClient inspired by MinimalHttpClient from msal unit tests
class FuzzHttpClient:
    """HTTP client returning data seeded by the fuzzer and no real connections"""
    def __init__(self, fdp, verify=True, proxies=None, timeout=None):
        # We keep these variables from the unit test implementation
        # in case some of the MSAL code uses it.
        self.session = requests.Session()
        self.session.verify = verify
        self.session.proxies = proxies
        self.timeout = timeout
        self.fdp = fdp

    def post(self, url, params=None, data=None, headers=None, **kwargs):
        return FuzzResponse(fdp = self.fdp)

    def get(self, url, params=None, headers=None, **kwargs):
        return FuzzResponse(fdp = self.fdp)

    def close(self):
        self.session.close()


class FuzzResponse(object):
    def __init__(self, fdp, requests_resp=None, status_code=None, text=None):
        # Over-approximate responses by creating a random Response object
        self._raw_resp = requests.Response()
        self.fdp = fdp
        self._raw_resp.status_code = self.fdp.ConsumeIntInRange(100, 599)
        self.text = self.fdp.ConsumeString(500)
        self.status_code = self._raw_resp.status_code

    def raise_for_status(self):
        if self._raw_resp is not None:
            self._raw_resp.raise_for_status()

def is_expected(error_list,error_msg):
    for error in error_list:
        if error in error_msg:
            return True
    return False

def TestInput(input_bytes):
    if len(input_bytes)<32:
        return 
    fdp = atheris.FuzzedDataProvider(input_bytes)
    authority = AuthorityBuilder(fdp.ConsumeString(50),fdp.ConsumeString(50))
    try:
        app = PublicClientApplication(
            client_id=fdp.ConsumeString(32),
            authority=authority,
            http_client=FuzzHttpClient(fdp) # Use fake Fuzz HTTP client
        )
        app.get_accounts()
    except (ValueError,KeyError) as e:
        error_list = [
            "tenant_discovery_endpoint",
            "Invalid IPv6 URL",
            "should consist of an https url with a minimum of one segment in a path",
            "netloc"
        ]
        if not is_expected(error_list,str(e)):
            raise e

    cert = "-----BEGIN CERTIFICATE-----%s-----END CERTIFICATE-----"%fdp.ConsumeString(200)
    extract_certs(cert)

def main():
    atheris.Setup(sys.argv, TestInput, enable_python_coverage=True)
    atheris.instrument_all()
    atheris.Fuzz()

if __name__ == "__main__":
    main()
