#!/usr/bin/python3
# Copyright 2026 Google LLC
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

import sys
import ssl
import atheris

from urllib3.util.ssl_ import (
    create_urllib3_context,
    resolve_cert_reqs,
    resolve_ssl_version,
)
from urllib3.exceptions import SSLError


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    
    try:
        ssl_versions = [None, ssl.PROTOCOL_TLS]
        
        # Add available protocol versions
        for proto in ['PROTOCOL_TLS_CLIENT', 'PROTOCOL_TLS_SERVER', 'PROTOCOL_TLSv1_2']:
            if hasattr(ssl, proto):
                ssl_versions.append(getattr(ssl, proto))
        
        ssl_version = fdp.PickValueInList(ssl_versions)
        
        cert_options = [None, ssl.CERT_NONE, ssl.CERT_OPTIONAL, ssl.CERT_REQUIRED]
        cert_reqs = fdp.PickValueInList(cert_options)
        
        ciphers = fdp.ConsumeString(sys.maxsize)[:100] if fdp.ConsumeBool() else None
        
        try:
            ctx = create_urllib3_context(
                ssl_version=ssl_version,
                cert_reqs=cert_reqs,
                ciphers=ciphers,
            )
            
            if fdp.ConsumeBool():
                ctx.check_hostname = fdp.ConsumeBool()
            
            if fdp.ConsumeBool():
                verify_mode = fdp.PickValueInList([ssl.CERT_NONE, ssl.CERT_OPTIONAL, ssl.CERT_REQUIRED])
                ctx.verify_mode = verify_mode
                
        except (SSLError, ValueError, TypeError):
            pass
        
        # Test cert requirement resolution
        cert_inputs = [None, "CERT_NONE", "CERT_OPTIONAL", "CERT_REQUIRED", 
                      "REQUIRED", "OPTIONAL", fdp.ConsumeString(sys.maxsize)[:20]]
        cert_input = fdp.PickValueInList(cert_inputs)
        try:
            resolve_cert_reqs(cert_input)
        except (SSLError, ValueError, TypeError):
            pass
        
        # Test SSL version resolution
        version_inputs = [None, "TLS", "TLSv1.2", fdp.ConsumeString(sys.maxsize)[:20]]
        version_input = fdp.PickValueInList(version_inputs)
        try:
            resolve_ssl_version(version_input)
        except (SSLError, ValueError, TypeError):
            pass
            
    except (SSLError, ValueError, TypeError, AttributeError):
        pass
    except Exception:
        pass


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
