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

import base64
import atheris
import sys
with atheris.instrument_imports():
    from msal.token_cache import *

#Create dummy token
def build_token(issuer="issuer",subject="subject",id="id",**claims): 
    return "header.%s.signature" % base64.b64encode(json.dumps(dict({
        "iss": issuer, "sub": subject, "aud": id,
        "exp": (time.time() + 100), "iat": time.time()
        }, **claims)).encode()).decode('utf-8')

#Create dummy response
def build_response(uid,utid,access_token,expires_in,token_type,**kwargs):
    response = {}
    if uid and utid:
        response["client_info"] = base64.b64encode(json.dumps({
            "uid": uid, "utid": utid,
        }).encode()).decode('utf-8')
    if access_token:
        response.update({
            "access_token": access_token,
            "expires_in": expires_in,
            "token_type": token_type,
        })
    response.update(kwargs)  # Pass-through key-value pairs as top-level fields
    return response

def is_expected(error_list,error_msg):
    for error in error_list:
        if error in error_msg:
            return True
    return False

def TestInput(input_bytes):
    if len(input_bytes)<32:
        return 

    fdp = atheris.FuzzedDataProvider(input_bytes)

    cache = TokenCache()

    client_id = fdp.ConsumeString(32)
    try:
        token = build_token(
          oid=fdp.ConsumeString(10), 
          preferred_username=fdp.ConsumeString(10), 
          id=client_id
        )
        cache.add({
          "client_id": client_id,
          "scope": ["s2", "s1", "s3"],
          "token_endpoint": "https://%s"%fdp.ConsumeString(20),
          "response": build_response(token_type=fdp.ConsumeString(5),
            uid=fdp.ConsumeString(5), utid=fdp.ConsumeString(5),
            expires_in=3600, access_token=fdp.ConsumeString(10),
            id_token=token, refresh_token=fdp.ConsumeString(10)),
        }, now=1000)
    except ValueError as e:
        error_list = [
           "netloc",
           "Invalid IPv6 URL",
           "should consist of an https url with a minimum of one segment in a path"
        ]
        if not is_expected(error_list,str(e)):
            raise e

def main():
    atheris.Setup(sys.argv, TestInput, enable_python_coverage=True)
    atheris.instrument_all()
    atheris.Fuzz()

if __name__ == "__main__":
    main()
