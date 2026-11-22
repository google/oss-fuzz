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
#
################################################################################
"""Prepares AV02 IVF seed corpus files from .ivf and Section-5 .obu inputs."""

import argparse
import pathlib
import shutil
import struct
import sys
from typing import Optional

DAV2D_OBU_TD = 2
MAX_LEB128_SHIFT = 56


def split_section5_obus(data: bytes) -> Optional[list[bytes]]:
  """Splits a Section-5 OBU stream into temporal units on DAV2D_OBU_TD."""
  pos = 0
  frames = []
  cur = bytearray()
  while pos < len(data):
    val = 0
    shift = 0
    start = pos
    while True:
      if pos >= len(data) or shift >= MAX_LEB128_SHIFT:
        return None
      v = data[pos]
      pos += 1
      val |= (v & 0x7F) << shift
      shift += 7
      if not v & 0x80:
        break
    if pos >= len(data) or pos + val > len(data):
      return None
    obu_type = (data[pos] >> 2) & 0x1F
    if obu_type == DAV2D_OBU_TD and cur:
      frames.append(bytes(cur))
      cur = bytearray()
    cur.extend(data[start:pos + val])
    pos += val
  if cur:
    frames.append(bytes(cur))
  return frames or None


def write_ivf(frames: list[bytes], out_path: pathlib.Path) -> None:
  """Writes temporal units to an AV02 IVF container file."""
  with out_path.open('wb') as f:
    f.write(
        struct.pack('<4sHH4sHHIIII', b'DKIF', 0, 32, b'AV02', 0, 0, 25, 1,
                    len(frames), 0))
    for idx, frame in enumerate(frames):
      f.write(struct.pack('<IQ', len(frame), idx))
      f.write(frame)


def process_source(src_path: pathlib.Path, dst_dir: pathlib.Path) -> None:
  """Copies .ivf files and converts valid .obu files from src_path."""
  if src_path.is_file():
    candidates = [src_path]
  else:
    candidates = sorted(src_path.rglob('*'))

  for path in candidates:
    if not path.is_file():
      continue
    suffix = path.suffix.lower()
    if suffix == '.ivf':
      shutil.copy2(path, dst_dir / path.name)
    elif suffix == '.obu':
      frames = split_section5_obus(path.read_bytes())
      if frames:
        write_ivf(frames, dst_dir / f'{path.stem}.ivf')


def main() -> int:
  """Parses CLI arguments and populates the output corpus directory."""
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument(
      '-o',
      '--output-dir',
      type=pathlib.Path,
      required=True,
      help='Destination directory for .ivf seed corpus files.',
  )
  parser.add_argument(
      'sources',
      nargs='+',
      type=pathlib.Path,
      help='Source files or directories containing .ivf or .obu streams.',
  )
  args = parser.parse_args()

  args.output_dir.mkdir(parents=True, exist_ok=True)
  for src in args.sources:
    process_source(src, args.output_dir)
  return 0


if __name__ == '__main__':
  sys.exit(main())
