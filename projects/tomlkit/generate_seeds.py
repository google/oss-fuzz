#!/usr/bin/env python3
"""
Seed generator script for tomlkit fuzzing.
Creates several highly diverse, valid, and spec-compliant TOML sample files.
"""

import sys
import os

SEEDS = {
    "basic_types.toml": """
# Basic data types and key value representations
title = "TOML Example"

[database]
server = "192.168.1.1"
ports = [ 8001, 8001, 8002 ]
connection_max = 5000
enabled = true
temp_targets = { cpu = 79.5, case = 40.0 }
""",

    "complex_arrays.toml": """
# Mixed nested arrays and inline structures
strings = [ "all", 'strings', \"\"\"are\"\"\", '''valid''' ]
numbers = [ [1, 2], [3, 4, 5] ]
nested_arrays_of_ints = [ [ 1, 2 ], [3, 4, 5] ]

# Inline tables
name = { first = "Tom", last = "Preston-Werner" }
point = { x = 1, y = 2, z = 3 }
""",

    "datetimes.toml": """
# Date and time formats specified by RFC 3339
odt1 = 1979-05-27T07:32:00Z
odt2 = 1979-05-27T00:32:00-07:00
odt3 = 1979-05-27T00:32:00.999999-07:00
ldt1 = 1979-05-27T07:32:00
ldt2 = 1979-05-27T07:32:00.999999
ld1 = 1979-05-27
lt1 = 07:32:00
lt2 = 07:32:00.999999
""",

    "multiline_strings.toml": """
# Test multi-line strings, escape sequences, and raw strings
key1 = \"\"\"
The quick brown \
fox jumps over \
the lazy dog.\"\"\"

key2 = '''
C:\\Users\\Maintainer\\Documents\\Project
\\\\Server\\Share\\Folder
'''

key3 = "I'm a string. \\\"You can quote me\\\". Name\\tJohn\\n"
""",

    "array_of_tables.toml": """
# Array of Tables (AoT) structure
[[products]]
name = "Hammer"
sku = 738552

[[products]]

[[products]]
name = "Nail"
sku = 28475
color = "gray"
""",

    "nested_tables.toml": """
# Nested dot keys and tables
[dog."tater.man"]
type.name = "pug"

[a.b.c]
d = "deep nesting"
"""
}


def main():
    if len(sys.argv) < 2:
        print("Usage: generate_seeds.py <output_directory>")
        sys.exit(1)

    out_dir = sys.argv[1]
    os.makedirs(out_dir, exist_ok=True)

    for filename, content in SEEDS.items():
        filepath = os.path.join(out_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content.strip())
    
    print(f"Successfully generated {len(SEEDS)} seeds in '{out_dir}'")


if __name__ == "__main__":
    main()
