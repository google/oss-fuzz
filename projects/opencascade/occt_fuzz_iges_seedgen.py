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
Seed generator for fuzzing OpenCASCADE's IGES parser.

IGES files are 80-column fixed-format ASCII. Each line has:
  - Columns 1-72: data
  - Column 73: section letter (S/G/D/P/T)
  - Columns 74-80: sequence number within that section

Sections: Start, Global, Directory Entry, Parameter Data, Terminate.
"""

import os
import sys

OUT_DIR = sys.argv[1] if len(sys.argv) > 1 else "occt_iges_seeds"


def iges_line(data, section, seq):
    """Format one 80-column IGES line."""
    d = data[:72].ljust(72)
    return f"{d}{section}{seq:7d}\n"


def make_minimal_iges():
    """Minimal valid IGES: start + global + terminate, no entities."""
    lines = []
    lines.append(iges_line("Minimal IGES file for fuzzing", "S", 1))
    # Global section: param delim, record delim, product ID, file name,
    # system ID, preprocessor version, int bits, max power of 10 float,
    # sig digits float, max power of 10 double, sig digits double,
    # product ID (receiving), scale, unit flag, unit name, max line weight,
    # max line weight width, date, resolution, max coordinate, author,
    # org, IGES version, drafting standard
    g = "1H,,1H;,7Hproduct,4Hfile,6Hsystem,5Hv1.0,32,75,6,75,15,,1.0,2,2HMM,1,0.01,15H20260410.120000,0.001,100.0,5Hfuzzy,3Horg,11,0;"
    lines.append(iges_line(g, "G", 1))
    lines.append(iges_line(f"S{1:7d}G{1:7d}D{0:7d}P{0:7d}", "T", 1))
    return "".join(lines)


def make_line_entity():
    """IGES with one Line entity (type 110)."""
    lines = []
    lines.append(iges_line("Line entity seed", "S", 1))
    g = "1H,,1H;,7Hproduct,4Hfile,6Hsystem,5Hv1.0,32,75,6,75,15,,1.0,2,2HMM,1,0.01,15H20260410.120000,0.001,100.0,5Hfuzzy,3Horg,11,0;"
    lines.append(iges_line(g, "G", 1))
    # Directory entry for line (type 110): 2 lines, 20 fields of 8 chars
    # Fields: type, param_ptr, structure, line_font, level, view, xform,
    #         label_assoc, status, seq
    de1 = "     110       1       0       0       0       0       0       000000000"
    de2 = "     110       0       0       1       0       0       0       0       0"
    lines.append(iges_line(de1, "D", 1))
    lines.append(iges_line(de2, "D", 2))
    # Parameter data: entity type, x1, y1, z1, x2, y2, z2
    p = "110,0.0,0.0,0.0,10.0,10.0,0.0;"
    lines.append(iges_line(f"{p:72s}", "P", 1))
    lines.append(iges_line(f"S{1:7d}G{1:7d}D{2:7d}P{1:7d}", "T", 1))
    return "".join(lines)


def make_long_param():
    """IGES with a parameter line containing a very long field (>80 chars)
    to trigger the char param[80] overflow in analiges.c."""
    lines = []
    lines.append(iges_line("Long param overflow seed", "S", 1))
    g = "1H,,1H;,7Hproduct,4Hfile,6Hsystem,5Hv1.0,32,75,6,75,15,,1.0,2,2HMM,1,0.01,15H20260410.120000,0.001,100.0,5Hfuzzy,3Horg,11,0;"
    lines.append(iges_line(g, "G", 1))
    de1 = "     110       1       0       0       0       0       0       000000000"
    de2 = "     110       0       0       1       0       0       0       0       0"
    lines.append(iges_line(de1, "D", 1))
    lines.append(iges_line(de2, "D", 2))
    # Long parameter without delimiter -- 90 chars of digits with no comma
    p = "110," + "1" * 90 + ",0.0,0.0,10.0,10.0,0.0;"
    # This will span multiple lines in the 72-col format
    lines.append(iges_line(p[:72], "P", 1))
    if len(p) > 72:
        lines.append(iges_line(p[72:144] if len(p) > 144 else p[72:], "P", 2))
    lines.append(iges_line(f"S{1:7d}G{1:7d}D{2:7d}P{2:7d}", "T", 1))
    return "".join(lines)


def make_hollerith_overflow():
    """IGES with a Hollerith string claiming more chars than available."""
    lines = []
    lines.append(iges_line("Hollerith overflow seed", "S", 1))
    g = "1H,,1H;,7Hproduct,4Hfile,6Hsystem,5Hv1.0,32,75,6,75,15,,1.0,2,2HMM,1,0.01,15H20260410.120000,0.001,100.0,5Hfuzzy,3Horg,11,0;"
    lines.append(iges_line(g, "G", 1))
    de1 = "     110       1       0       0       0       0       0       000000000"
    de2 = "     110       0       0       1       0       0       0       0       0"
    lines.append(iges_line(de1, "D", 1))
    lines.append(iges_line(de2, "D", 2))
    # Hollerith: 9999H followed by short data -- nbcarH will be huge
    p = "110,9999Hshort,0.0,0.0,10.0,10.0,0.0;"
    lines.append(iges_line(p[:72], "P", 1))
    lines.append(iges_line(f"S{1:7d}G{1:7d}D{2:7d}P{1:7d}", "T", 1))
    return "".join(lines)


def make_many_entities():
    """IGES with 5 line entities to exercise iteration paths."""
    lines = []
    lines.append(iges_line("Multi entity seed", "S", 1))
    g = "1H,,1H;,7Hproduct,4Hfile,6Hsystem,5Hv1.0,32,75,6,75,15,,1.0,2,2HMM,1,0.01,15H20260410.120000,0.001,100.0,5Hfuzzy,3Horg,11,0;"
    lines.append(iges_line(g, "G", 1))
    d_seq = 1
    p_seq = 1
    for i in range(5):
        de1 = f"     110{p_seq:8d}       0       0       0       0       0       000000000"
        de2 = f"     110       0       0       1       0       0       0       0       0"
        lines.append(iges_line(de1, "D", d_seq))
        lines.append(iges_line(de2, "D", d_seq + 1))
        d_seq += 2
        p = f"110,{i*10}.0,0.0,0.0,{i*10+10}.0,10.0,0.0;"
        lines.append(iges_line(p[:72], "P", p_seq))
        p_seq += 1
    lines.append(iges_line(f"S{1:7d}G{1:7d}D{d_seq-1:7d}P{p_seq-1:7d}", "T", 1))
    return "".join(lines)


def make_transform_entity():
    """IGES with a transformation matrix entity (type 124)."""
    lines = []
    lines.append(iges_line("Transform matrix seed", "S", 1))
    g = "1H,,1H;,7Hproduct,4Hfile,6Hsystem,5Hv1.0,32,75,6,75,15,,1.0,2,2HMM,1,0.01,15H20260410.120000,0.001,100.0,5Hfuzzy,3Horg,11,0;"
    lines.append(iges_line(g, "G", 1))
    de1 = "     124       1       0       0       0       0       0       000000000"
    de2 = "     124       0       0       1       0       0       0       0       0"
    lines.append(iges_line(de1, "D", 1))
    lines.append(iges_line(de2, "D", 2))
    # 3x4 matrix (R11,R12,R13,T1, R21,R22,R23,T2, R31,R32,R33,T3)
    p = "124,1.0,0.0,0.0,0.0,0.0,1.0,0.0,0.0,0.0,0.0,1.0,0.0;"
    lines.append(iges_line(p[:72], "P", 1))
    if len(p) > 72:
        lines.append(iges_line(p[72:], "P", 2))
    lines.append(iges_line(f"S{1:7d}G{1:7d}D{2:7d}P{1:7d}", "T", 1))
    return "".join(lines)


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    seeds = {
        "minimal.igs": make_minimal_iges(),
        "line_entity.igs": make_line_entity(),
        "long_param.igs": make_long_param(),
        "hollerith_overflow.igs": make_hollerith_overflow(),
        "many_entities.igs": make_many_entities(),
        "transform.igs": make_transform_entity(),
    }
    for name, content in seeds.items():
        path = os.path.join(OUT_DIR, name)
        with open(path, "w") as f:
            f.write(content)
        print(f"  {len(content):5d}B  {name}")
    print(f"\ntotal seeds: {len(seeds)}")


if __name__ == "__main__":
    main()
