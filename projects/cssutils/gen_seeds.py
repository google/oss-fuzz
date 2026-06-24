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

import os
import sys


def generate_seeds(output_dir):
    """Generate seed corpus for cssutils fuzzer"""
    os.makedirs(output_dir, exist_ok=True)
    
    seeds = {
        # Basic CSS rules
        "basic.css": b"div { color: red; background: blue; }",
        
        # Complex selectors
        "selectors.css": b"""
            #id, .class, [attr], div > p, div + p, div ~ p,
            :hover, :focus, :nth-child(2n), ::before, ::after,
            :not(.class), :is(div, span) { margin: 0; }
        """,
        
        # At-rules
        "atrules.css": b"""
            @import url("style.css");
            @media screen and (max-width: 768px) { body { margin: 0; } }
            @keyframes fade { from { opacity: 0; } to { opacity: 1; } }
            @font-face { font-family: "Test"; src: url("font.woff"); }
            @supports (display: grid) { .grid { display: grid; } }
        """,
        
        # URL values (potential security relevant)
        "urls.css": b"""
            div { background: url("image.png"); }
            div { background: url('data:image/png;base64,abc123'); }
            @import url("http://example.com/style.css");
        """,
        
        # Complex values
        "values.css": b"""
            div { 
                color: rgba(255, 0, 0, 0.5);
                width: calc(100% - 20px);
                transform: rotate(45deg) scale(1.5);
                background: linear-gradient(to right, red, blue);
                font: 14px/1.5 Arial, sans-serif;
            }
        """,
        
        # Edge cases
        "edge.css": b"""
            /* Comments */
            .class { content: "string with quotes"; }
            #id { font-family: "Font Name", serif; }
            [attr="value"] { color: red; }
            div { margin: 0 !important; }
        """,
        
        # Empty and minimal
        "empty.css": b"",
        "minimal.css": b"a{color:red}",
        
        # Malformed/broken (for robustness testing)
        "broken.css": b"div { color: ",
        "invalid.css": b"not valid css {{{",
        "unclosed.css": b"div { content: 'unclosed string",
        
        # Unicode
        "unicode.css": "div { content: '日本語'; }".encode('utf-8'),
        
        # Deep nesting
        "nested.css": b"""
            div { 
                span { 
                    p { 
                        a { color: red; }
                    }
                }
            }
        """,
    }
    
    for name, content in seeds.items():
        path = os.path.join(output_dir, name)
        with open(path, "wb") as f:
            f.write(content)
        print(f"Created {path} ({len(content)} bytes)")
    
    print(f"\nGenerated {len(seeds)} seed files in {output_dir}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <output_directory>")
        sys.exit(1)
    
    generate_seeds(sys.argv[1])