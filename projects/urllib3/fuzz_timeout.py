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

from urllib3.util.timeout import Timeout
from urllib3.exceptions import TimeoutError


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    
    try:
        connect = fdp.ConsumeFloatInRange(0.001, 300.0)
        read = fdp.ConsumeFloatInRange(0.001, 300.0)
        total = fdp.ConsumeFloatInRange(0.001, 300.0)
        
        timeout = Timeout(connect=connect, read=read, total=total)
        
        # Clone with new values
        new_connect = fdp.ConsumeFloatInRange(0.001, 300.0) if fdp.ConsumeBool() else None
        new_read = fdp.ConsumeFloatInRange(0.001, 300.0) if fdp.ConsumeBool() else None
        new_total = fdp.ConsumeFloatInRange(0.001, 300.0) if fdp.ConsumeBool() else None
        
        cloned = timeout.clone(connect=new_connect, read=new_read, total=new_total)
        
        # Test from_float with different inputs
        val = fdp.ConsumeFloatInRange(0.001, 300.0)
        timeout_single = Timeout.from_float(val)
        
        # Tuple form
        t1 = fdp.ConsumeFloatInRange(0.001, 300.0)
        t2 = fdp.ConsumeFloatInRange(0.001, 300.0)
        timeout_tuple = Timeout.from_float((t1, t2))
        
        # Edge cases
        edges = [0.0, -1.0, float('inf'), float('-inf'), float('nan'), None]
        for edge in edges:
            try:
                if edge is not None:
                    Timeout(connect=edge, read=1.0)
            except (ValueError, TypeError):
                pass
        
        # String input
        s = fdp.ConsumeString(sys.maxsize)[:50]
        try:
            Timeout.from_float(s)
        except (ValueError, TypeError):
            pass
            
    except (TimeoutError, ValueError, TypeError):
        pass
    except Exception:
        pass


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
