#!/usr/bin/env python3
# Copyright 2024 Google LLC
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

import io
import signal
import sys

import atheris

with atheris.instrument_imports():
    import cssutils
    import cssutils.serialize
    import logging

# Suppress cssutils logging to stderr
cssutils.log.setLevel(logging.CRITICAL)


class TimeoutError(Exception):
    pass


def timeout_handler(signum, frame):
    raise TimeoutError("Parsing timeout")


# Set up timeout to prevent ReDoS from hanging fuzzer indefinitely
signal.signal(signal.SIGALRM, timeout_handler)


def parse_with_timeout(data, timeout_sec=5):
    """Parse CSS with timeout protection"""
    signal.alarm(timeout_sec)
    try:
        return cssutils.parseString(data)
    finally:
        signal.alarm(0)


def fuzz_stylesheet(fdp):
    """Fuzz full stylesheet parsing"""
    data = fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 4096))
    try:
        sheet = parse_with_timeout(data)
        if sheet is None:
            return
        
        # Exercise various properties to increase coverage
        _ = sheet.cssText
        _ = sheet.cssRules
        
        for rule in sheet.cssRules:
            _ = rule.cssText
            _ = rule.type
            if hasattr(rule, 'selectorText'):
                _ = rule.selectorText
            if hasattr(rule, 'style'):
                for prop in rule.style:
                    _ = prop.name
                    _ = prop.value
                    _ = prop.priority
    except (TimeoutError, Exception):
        pass


def fuzz_style_attribute(fdp):
    """Fuzz inline style attribute parsing"""
    try:
        text = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 1024))
        style = cssutils.parseStyle(text)
        if style:
            _ = style.cssText
            for prop in style:
                _ = prop.name
                _ = prop.value
    except (TimeoutError, Exception):
        pass


def fuzz_url_values(fdp):
    """Fuzz URL values which may have security implications"""
    try:
        url = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 512))
        css = f'background-image: url("{url}");'
        sheet = parse_with_timeout(css.encode('utf-8', errors='ignore'))
        if sheet:
            for rule in sheet.cssRules:
                if hasattr(rule, 'style'):
                    _ = rule.style.getPropertyValue('background-image')
    except (TimeoutError, Exception):
        pass


def fuzz_import_rules(fdp):
    """Fuzz @import rules"""
    try:
        url = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 512))
        css = f'@import url("{url}");'
        sheet = parse_with_timeout(css.encode('utf-8', errors='ignore'))
        if sheet:
            for rule in sheet.cssRules:
                if hasattr(rule, 'href'):
                    _ = rule.href
    except (TimeoutError, Exception):
        pass


def fuzz_serialization(fdp):
    """Fuzz serialization with preferences"""
    try:
        data = fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 2048))
        sheet = parse_with_timeout(data)
        if sheet is None:
            return
        
        prefs = cssutils.serialize.Preferences()
        prefs.omitLastSemicolon = fdp.ConsumeBool()
        prefs.keepEmptyRules = fdp.ConsumeBool()
        prefs.indentClosingBrace = fdp.ConsumeBool()
        prefs.normalizedVarNames = fdp.ConsumeBool()
        
        serializer = cssutils.CSSSerializer(prefs)
        _ = serializer.serialize(sheet)
    except (TimeoutError, Exception):
        pass


def fuzz_selectors(fdp):
    """Fuzz CSS selector parsing"""
    try:
        selector = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 512))
        css = f'{selector} {{ color: red; }}'
        sheet = parse_with_timeout(css.encode('utf-8', errors='ignore'))
    except (TimeoutError, Exception):
        pass


# Fuzzing strategies
STRATEGIES = [
    fuzz_stylesheet,
    fuzz_style_attribute,
    fuzz_url_values,
    fuzz_import_rules,
    fuzz_serialization,
    fuzz_selectors,
]


def TestOneInput(data):
    """Main entry point for libFuzzer"""
    if len(data) < 1:
        return
    
    fdp = atheris.FuzzedDataProvider(data)
    
    # Select strategy based on first byte
    strategy_idx = fdp.ConsumeIntInRange(0, len(STRATEGIES) - 1)
    strategy = STRATEGIES[strategy_idx]
    
    try:
        strategy(fdp)
    except Exception:
        # Catch-all to prevent fuzzer from stopping
        pass


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()