#!/usr/bin/python3
# Copyright 2023 Google LLC
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

import os
import sys
import atheris
import cachetools
import random
import datetime
from threading import Lock

def get_ttu(_key, value, now):
    # assume value.ttl contains the item's time-to-live in hours
    return datetime.datetime.now() + random.random() * datetime.timedelta(days=200000)

def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    cache_size = fdp.ConsumeIntInRange(1,32)
    cache_ttl = fdp.ConsumeProbability()
    cache_lock = None
    if fdp.ConsumeBool():
        cache_lock = Lock()

    # Random caching types
    CACHE_TYPES = [
        {},
        cachetools.FIFOCache(maxsize=cache_size),
        cachetools.LFUCache(maxsize=cache_size),
        cachetools.LRUCache(maxsize=cache_size),
        cachetools.MRUCache(maxsize=cache_size),
        cachetools.RRCache(maxsize=cache_size, choice=random.choice),
        cachetools.TTLCache(maxsize=cache_size, ttl=cache_ttl),
        cachetools.TLRUCache(maxsize=cache_size, ttu=get_ttu, timer=datetime.datetime.now)
    ]

    # Generate a random cached function
    @cachetools.cached(cache=fdp.PickValueInList(CACHE_TYPES), lock=cache_lock, info=fdp.ConsumeBool())
    def fib(n):
        return n if n < 2 else fib(n - 1) + fib(n - 2)
    
    for i in range(20):
        fib(fdp.ConsumeIntInRange(1, 20))
        # Try and get coverage of different properties
        try:
            fib.maxsize()
            fib.currsize()
        except AttributeError:
            pass

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    atheris.instrument_all()
    main()