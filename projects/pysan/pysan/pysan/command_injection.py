from typing import Optional

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
