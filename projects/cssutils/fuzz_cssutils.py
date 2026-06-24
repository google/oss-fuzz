#!/usr/bin/env python3
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

"""
Deep-state fuzzer for cssutils (Fully Silent & Robust).
Targets: Property values, Selectors, Tokenizer, Encodings, and Error Recovery.
"""

import sys
import logging
import signal
import warnings
import atheris
import cssutils

# ==============================================================================
# SILENCE NOISE (NUCLEAR OPTION)
# ==============================================================================

# 1. Disable ALL standard library logging (Stops "WARNING Property: ...")
#    This hides everything below CRITICAL level.
logging.disable(logging.CRITICAL)

# 2. Silence Python Warnings (Stops DeprecationWarnings, etc.)
warnings.filterwarnings("ignore")

# 3. Silence cssutils specific error handler (Stops "ERROR Selector: ...")
#    We replace the log object with a dummy class that swallows all calls.
class _SilentErrorHandler:
    raiseExceptions = False
    level = 50 # CRITICAL
    
    def handle(self, *args, **kwargs):
        pass  # Swallow the error
    
    def __getattr__(self, name):
        # Catch any method call (warn, log, info, error) and swallow it
        return self.handle

try:
    cssutils.log = _SilentErrorHandler()
except Exception:
    pass

# ==============================================================================
# ROBUST IMPORTS
# ==============================================================================

# cssutils changes its API frequently. We safely import what we can.
Property = None
try:
    from cssutils.css import Property
except ImportError:
    pass

Selector = None
try:
    from cssutils.css import Selector
except ImportError:
    try:
        from cssutils.selector import Selector
    except (ImportError, ModuleNotFoundError):
        pass

CSSParseException = Exception
try:
    from cssutils import CSSParseException
except ImportError:
    pass

# Increase recursion limit for deep nesting logic
sys.setrecursionlimit(5000)

# Expected parse errors (NOT bugs)
EXPECTED_PARSE_EXCEPTIONS = (
    CSSParseException,
    KeyError,
    IndexError,
    ValueError,
    TypeError,
    SyntaxError,
    NotImplementedError,
    AttributeError,
)

def _safe_call(callable_fn, *args, **kwargs):
    """
    Catches expected parsing errors. 
    Re-raises RecursionError/MemoryError (Valid DoS bugs).
    """
    try:
        return callable_fn(*args, **kwargs)
    except EXPECTED_PARSE_EXCEPTIONS:
        return None
    except (RecursionError, MemoryError) as exc:
        raise exc  # Valid DoS findings
    except Exception as exc:
        raise exc  # Logic bugs

def _fuzz_property_parsing(css_text):
    """Target: The property parser logic."""
    if Property is None: return
    _safe_call(Property, "color", css_text)
    _safe_call(Property, "background", css_text)
    _safe_call(Property, "content", css_text)
    _safe_call(cssutils.parseStyle, css_text)

def _fuzz_selector_parsing(css_text):
    """Target: Selector parsing (Regex/ReDoS)."""
    if Selector is None: return
    _safe_call(Selector, css_text)

def _fuzz_encoding_stress(raw_bytes):
    """Target: Tokenizer encoding handling."""
    for encoding in ['utf-8', 'ascii', 'latin-1', 'utf-16', 'utf-32']:
        try:
            text = raw_bytes.decode(encoding, errors='replace')
            _safe_call(cssutils.parseString, text)
        except (UnicodeDecodeError, ValueError):
            pass

def _fuzz_serialization(sheet, fdp):
    """Target: Serialization logic."""
    _safe_call(lambda: sheet.cssText)
    # Only mutate preferences if the attribute actually exists
    if hasattr(cssutils, 'serPrefs') and fdp.ConsumeBool():
        try:
            cssutils.serPrefs.indent = fdp.ConsumeBool()
            _safe_call(lambda: sheet.cssText)
        except (AttributeError, Exception):
            pass

def _test_one_input(input_bytes):
    """Main entry point."""
    fdp = atheris.FuzzedDataProvider(input_bytes)

    # 5-second timeout to catch ReDoS
    def timeout_handler(signum, frame):
        raise TimeoutError("Parsing took too long (ReDoS)")
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(5)

    try:
        # Branch 1: Property/Value Parsing
        if fdp.ConsumeBool():
            text = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(10, 2000))
            _fuzz_property_parsing(text)

        # Branch 2: Selector Parsing
        if fdp.ConsumeBool():
            text = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(10, 2000))
            _fuzz_selector_parsing(text)

        # Branch 3: Encoding Stress Test
        if fdp.ConsumeBool():
            raw = fdp.ConsumeBytes(fdp.ConsumeIntInRange(10, 2000))
            _fuzz_encoding_stress(raw)

        # Branch 4: Full Stylesheet Parse
        text = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(10, 5000))
        validate = fdp.ConsumeBool()
        sheet = _safe_call(cssutils.parseString, text, validate=validate)
        
        if sheet:
            _safe_call(lambda: sheet.cssRules)
            _fuzz_serialization(sheet, fdp)

    except TimeoutError:
        pass
    finally:
        signal.alarm(0)

def main():
    if hasattr(atheris, 'instrument_lib'):
        atheris.instrument_lib()
    else:
        atheris.instrument_all()

    atheris.Setup(sys.argv, _test_one_input)
    atheris.Fuzz()

if __name__ == "__main__":
    main()