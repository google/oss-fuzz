#!/usr/bin/env python3
import sys
import math
import datetime
import tomllib
import atheris

with atheris.instrument_imports():
    import tomlkit
    from tomlkit.exceptions import TOMLKitError
    try:
        import tomlkit.items as tomlkit_items
    except ImportError:
        tomlkit_items = None


def to_primitive(val):
    """Recursively converts tomlkit elements into standard Python primitives."""
    if isinstance(val, dict):
        return {k: to_primitive(v) for k, v in val.items()}
    if isinstance(val, list):
        return [to_primitive(v) for v in val]
    
    # Normalize datetimes to bypass class subclassing discrepancies
    if isinstance(val, datetime.datetime):
        return datetime.datetime(
            val.year, val.month, val.day,
            val.hour, val.minute, val.second,
            val.microsecond, val.tzinfo
        )
    if isinstance(val, datetime.date):
        return datetime.date(val.year, val.month, val.day)
    if isinstance(val, datetime.time):
        return datetime.time(
            val.hour, val.minute, val.second,
            val.microsecond, val.tzinfo
        )
    
    # Custom Bool in tomlkit does not inherit from bool (since bool is final)
    if type(val).__name__ == "Bool" or (tomlkit_items and isinstance(val, tomlkit_items.Bool)):
        return bool(val)
        
    if isinstance(val, bool):
        return bool(val)
    if isinstance(val, int):
        return int(val)
    if isinstance(val, float):
        return float(val)
    if isinstance(val, str):
        return str(val)
        
    return val


def is_equal(v1, v2):
    """Performs deep comparison, safely handling IEEE 754 NaN equality."""
    if type(v1) != type(v2):
        if isinstance(v1, (int, float)) and isinstance(v2, (int, float)):
            pass
        else:
            return False

    if isinstance(v1, dict):
        if set(v1.keys()) != set(v2.keys()):
            return False
        return all(is_equal(v1[k], v2[k]) for k in v1)
    
    if isinstance(v1, (list, tuple)):
        if len(v1) != len(v2):
            return False
        return all(is_equal(x, y) for x, y in zip(v1, v2))
    
    if isinstance(v1, float) and isinstance(v2, float):
        if math.isnan(v1) and math.isnan(v2):
            return True
        return v1 == v2
    
    return v1 == v2


def TestOneInput(data):
    try:
        toml_str = data.decode("utf-8")
    except UnicodeDecodeError:
        return

    # Reference baseline parsing
    tomllib_failed = False
    tomllib_data = None
    try:
        tomllib_data = tomllib.loads(toml_str)
    except Exception:
        tomllib_failed = True

    # Main tomlkit parse
    tomlkit_failed = False
    tomlkit_doc = None
    try:
        tomlkit_doc = tomlkit.parse(toml_str)
    except TOMLKitError:
        tomlkit_failed = True
    except (ValueError, TypeError, KeyError, IndexError, AttributeError) as e:
        # Standard exceptions raised outside TOMLKitError indicate unhandled bugs
        raise AssertionError(f"Unhandled exception: {type(e).__name__}: {e}") from e

    # Differential parsing check
    if not tomllib_failed and tomlkit_failed:
        raise AssertionError(f"Compliance discrepancy: tomllib parsed but tomlkit failed. Input: {repr(toml_str)}")

    if not tomlkit_failed and tomlkit_doc is not None:
        # Validate semantic correctness
        if not tomllib_failed:
            prim_tomlkit = to_primitive(tomlkit_doc)
            prim_tomllib = to_primitive(tomllib_data)
            if not is_equal(prim_tomlkit, prim_tomllib):
                raise AssertionError(f"Semantic mismatch!\ntomllib: {prim_tomllib}\ntomlkit: {prim_tomlkit}")

        # Round-trip serialization validation
        try:
            dumped = tomlkit.dumps(tomlkit_doc)
        except Exception as e:
            raise AssertionError(f"Failed to serialize parsed AST: {type(e).__name__}: {e}") from e

        try:
            reparsed = tomlkit.parse(dumped)
        except Exception as e:
            raise AssertionError(f"Failed to parse serialized output: {type(e).__name__}: {e}\nOutput: {repr(dumped)}") from e

        # AST mutation robustness validation
        try:
            for key in list(tomlkit_doc.keys()):
                original = tomlkit_doc[key]
                tomlkit_doc[key] = "fuzzed_mutated_value"
                tomlkit.dumps(tomlkit_doc)
                
                if isinstance(original, dict):
                    original["fuzzed_sub_key"] = 12345
                    tomlkit.dumps(tomlkit_doc)
                    
                tomlkit_doc[key] = original
        except Exception as e:
            raise AssertionError(f"AST mutation crash: {type(e).__name__}: {e}") from e


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
