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
with atheris.instrument_imports():
    from msal import PublicClientApplication
    from msal.application import extract_certs
    from msal.authority import AuthorityBuilder

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
        app = PublicClientApplication(client_id=fdp.ConsumeString(32),authority=authority)
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
