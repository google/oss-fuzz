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

from urllib3.util.retry import Retry
from urllib3.exceptions import (
    MaxRetryError,
    RetryError,
    ConnectTimeoutError,
    ReadTimeoutError,
)


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    
    try:
        total = fdp.ConsumeIntInRange(0, 10)
        connect = fdp.ConsumeIntInRange(0, 5)
        read = fdp.ConsumeIntInRange(0, 5)
        redirect = fdp.ConsumeIntInRange(0, 5)
        backoff = fdp.ConsumeFloatInRange(0.0, 10.0)
        
        retry = Retry(
            total=total,
            connect=connect,
            read=read,
            redirect=redirect,
            backoff_factor=backoff,
            raise_on_redirect=fdp.ConsumeBool(),
            raise_on_status=fdp.ConsumeBool(),
        )
        
        # Test with various status codes
        status_list = []
        for _ in range(fdp.ConsumeIntInRange(0, 10)):
            status_list.append(fdp.ConsumeIntInRange(400, 599))
        
        if status_list:
            retry = retry.new(status_forcelist=status_list)
        
        # Check retry behavior
        for _ in range(fdp.ConsumeIntInRange(0, 20)):
            status = fdp.ConsumeIntInRange(100, 599)
            method = fdp.PickValueInList(["GET", "POST", "PUT", "DELETE", "HEAD"])
            
            try:
                retry.is_retry(method, status, fdp.ConsumeBool())
            except (ValueError, TypeError):
                pass
        
        # Test retry-after parsing
        retry_after = fdp.ConsumeString(sys.maxsize)[:100]
        try:
            retry.get_retry_after(retry_after)
        except (ValueError, TypeError):
            pass
            
    except (MaxRetryError, RetryError, ConnectTimeoutError, ReadTimeoutError, ValueError, TypeError):
        pass
    except Exception:
        pass


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
