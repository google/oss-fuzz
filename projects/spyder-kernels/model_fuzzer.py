# Copyright 2021 Google LLC
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

import sys
import atheris
import json
from spyder_kernels.console.kernel import SpyderKernel

def fuzzed_spyder_kernel(fuzzer_input):
    try:
        # Convert fuzzed input to a string
        input_str = fuzzer_input.decode('utf-8', errors='ignore')

        # Try to parse it as JSON (simulate an API request or configuration)
        config = json.loads(input_str)

        # Start Spyder kernel with fuzzed config (this is a simplified example)
        kernel = SpyderKernel(config=config)
        kernel.do_start()  # Start the kernel
        kernel.do_shutdown(restart=False)  # Shutdown the kernel

    except Exception as e:
        # Handle exceptions for any issues
        pass

def main():
    atheris.Setup(sys.argv, fuzzed_spyder_kernel)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
