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
import atheris

import urllib3
from urllib3.poolmanager import PoolManager
from urllib3.exceptions import (
    ClosedPoolError,
    EmptyPoolError,
    HostChangedError,
    LocationValueError,
    MaxRetryError,
    NewConnectionError,
    RequestError,
    SSLError,
    TimeoutError,
    HTTPError,
)


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    
    try:
        # Vary pool configuration
        num_pools = fdp.ConsumeIntInRange(1, 100)
        maxsize = fdp.ConsumeIntInRange(1, 50)
        block = fdp.ConsumeBool()
        timeout = fdp.ConsumeFloatInRange(0.1, 30.0)
        
        pool_manager = PoolManager(
            num_pools=num_pools,
            maxsize=maxsize,
            block=block,
            timeout=timeout,
        )
        
        scheme = fdp.PickValueInList(["http", "https"])
        host = fdp.ConsumeString(sys.maxsize)[:50]
        port = fdp.ConsumeIntInRange(1, 65535)
        
        try:
            pool = pool_manager.connection_from_host(host, port, scheme)
        except (LocationValueError, ValueError):
            pass
        
        if fdp.ConsumeBool():
            pool_manager.clear()
            
    except (
        ClosedPoolError,
        EmptyPoolError,
        HostChangedError,
        MaxRetryError,
        NewConnectionError,
        RequestError,
        SSLError,
        TimeoutError,
        HTTPError,
        ValueError,
        TypeError,
    ):
        pass
    except Exception:
        pass


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
