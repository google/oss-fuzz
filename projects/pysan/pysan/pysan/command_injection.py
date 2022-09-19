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


def get_all_substr_prefixes(main_str, sub_str):
    idx = 0
    while True:
        idx = main_str.find(sub_str, idx)
        if idx == -1:
            return
        yield main_str[0:idx]
        # Increase idx the length of the substring from the current position
        # where an occurence of the substring was found.
        idx += len(sub_str)


def check_code_injection_match(
    elem, check_unquoted = False
) -> Optional[str]:
    # Check exact match
    if elem == "exec-sanitizer":
        return "Explicit command injection found."

    # Check potential for injecting into a string
    if "FROMFUZZ" in elem:
        if check_unquoted:
            # return true if any index is unquoted
            for sub_str in get_all_substr_prefixes(elem, "FROMFUZZ"):
                if sub_str.count("\"") % 2 == 0:
                    return "Fuzzer controlled content in data. Code injection potential."

            # Return None if all fuzzer taints were quoted
            return None
        return "Fuzzer controlled content in data. Code injection potential."
    return None


def pysan_hook_subprocess_Popen(cmd, **kwargs):
    """Hook for subprocess.Popen"""
    if "shell" in kwargs and kwargs["shell"] is True:
        arg_shell = True
    else:
        arg_shell = False

    # Command injections depend on whether the first argument is a list of
    # strings or a string. Handle this now.
    if type(cmd) is str:
        res = check_code_injection_match(cmd, check_unquoted=True)
        if res != None:
            # if shell arg is true and string is tainted and unquoted that's a
            # definite code injection.
            if arg_shell is True:
                raise Exception("Code injection in Popen")

            # Otherwise it's a maybe.
            raise Exception(
                    f"Potental code injection in subprocess.Popen\n{res}")


    # Check for hg command injection
    if cmd[0] == "hg":
        # Check if the arguments are controlled by the fuzzer, and this given
        # arg is not preceded by --
        found_dashes = False
        for idx in range(1, len(cmd)):
            if cmd[0] == "--":
                found_dashes = True
            if not found_dashes and check_code_injection_match(cmd[idx]):
                raise Exception(
                    f"""command injection likely by way of mercurial. The following
                      command {str(cmd)} is executed, and if you substitute {cmd[idx]}
                      with \"--config=alias.init=!touch HELLO_PY\" then you will
                      create HELLO_PY"""
                )


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
