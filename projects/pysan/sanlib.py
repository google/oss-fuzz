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
#
################################################################################

from typing import Optional
import functools

sanitizer_log_level = 0
def sanitizer_log(msg, log_level):
    global sanitizer_log_level
    if log_level >= sanitizer_log_level:
        print(f"[PYSAN] {msg}")


def sanitize_hook(function, hook = None, post_hook = None):
    """Hook a function.

    Hooks can be placed pre and post function call. At least one hook is
    needed.
    """
    if hook is None and post_hook is None:
        raise Exception("Some hooks must be included")

    @functools.wraps(function)
    def run(*args, **kwargs):
        sanitizer_log(f"Hook start {str(function)}", 0)
        # Call hook
        hook(*args, **kwargs)

        # Call the original function in the even the hook did not indicate
        # failure.
        ret = function(*args, **kwargs)

        # Enable post hooking. This can be used to e.g. check
        # state of file system.
        if post_hook is not None:
            post_hook(*args, **kwargs)
        sanitizer_log(f"Hook end {str(function)}", 0)
        return ret
    return run


def check_code_injection_match(elem) -> Optional[str]:
    # Check exact match
    if elem == "exec-sanitizer":
        return "Explicit command injection found."

    # Check potential for injecting into a string
    if "FROMFUZZ" in elem:
        return "Fuzzer controlled content in data. Code injection potential."
    return None


def pysan_hook_subprocess_Popen(cmd, **kwargs):
    """Hook for subprocess.Popen"""
    # Check first argument
    if type(cmd) is str:
        res = check_code_injection_match(cmd)
        if res != None:
            raise Exception(
                    f"Potental code injection in subprocess.Popen\n{res}")
    if type(cmd) is list:
        for elem in cmd:
            res = check_code_injection_match(elem)
            if res != None:
                print(res)
                raise Exception(
                    f"Potential code injection in subprocess.Popen\n{res}")


def pysan_hook_os_system(cmd):
    """Hook for os.system"""
    res = check_code_injection_match(cmd)
    if res != None:
        raise Exception(f"Potential code injection by way of os.system\n{res}")


def pysan_hook_eval(cmd):
    """Hook for eval"""
    res = check_code_injection_match(cmd)
    if res != None:
        raise Exception(f"Potential code injection by way of eval\n{res}")

def pysan_add_hook(target, pre_hook = None, post_hook = None):
    return sanitize_hook(target, hook = pre_hook, post_hook = post_hook)

# Do the actual hooks
def pysan_add_hooks():
    import os
    import subprocess
    #eval = pysan_add_hook(eval, pre_hook = pysan_hook_eval)
    os.system = pysan_add_hook(os.system,
                               pre_hook = pysan_hook_os_system)
    subprocess.Popen = pysan_add_hook(subprocess.Popen,
                                      pre_hook = pysan_hook_subprocess_Popen)


pysan_add_hooks()
