#!/usr/bin/env python
# Copyright 2016 Google Inc.
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

from __future__ import print_function
import logging
import os
import re
import sys
import zipfile


logging.basicConfig(level=logging.INFO, format='INFO: %(message)s')
CODEC_NAME_REGEXP = re.compile(r'codec_id_(.+?)_fuzzer')


def get_fuzzer_tags(fuzzer_name):
  """Extract tags (are used to filter samples) from the given fuzzer name."""
  tags = []
  fuzzer_name = fuzzer_name.lower()
  # All subtitle samples are in 'sub' directory, need to add 'sub' tag manually.
  if 'subtitle' in fuzzer_name:
    tags.append('sub')
  m = CODEC_NAME_REGEXP.search(fuzzer_name)
  if m:
    codec_name = m.group(1)
    # Some names are complex, need to split them and filter common strings.
    codec_name_parts = codec_name.split('_')
    for codec in codec_name_parts:
      # Remove common strings from codec names like 'mpeg1video' or 'msvideo1'.
      codec = codec.split('video')[0]
      codec = codec.split('audio')[0]
      codec = codec.split('subtitle')[0]
      codec = codec.split('text')[0]
      if codec:
        # Some codec names have trailing characters: 'VP6F','FLV1', 'JPEGLS'.
        # Use only first 3 characters for long enough codec names.
        if len(codec) > 3:
          tags.append(codec[:3])
        else:
          tags.append(codec)

  return tags


def parse_corpus(corpus_directory):
  """Recursively list all files in the given directory and ignore checksums."""
  all_corpus_files = []
  for root, dirs, files in os.walk(corpus_directory):
    for filename in files:
      # Skip checksum files, they are useless in corpus.
      if 'md5sum' in filename:
        continue
      path = os.path.join(root, filename)
      all_corpus_files.append(path)

  logging.info('Parsed %d corpus files from %s' % (len(all_corpus_files),
                                                   corpus_directory))
  return all_corpus_files


def parse_fuzzers(fuzzers_directory):
  """Recursively list all fuzzers in the given directory."""
  all_fuzzers = []
  for filename in os.listdir(fuzzers_directory):
    # Skip non-ffmpeg and non-fuzzer files in the given directory,
    if not filename.startswith('ffmpeg_') or not filename.endswith('_fuzzer'):
      continue
    fuzzer_path = os.path.join(fuzzers_directory, filename)
    all_fuzzers.append(fuzzer_path)

  logging.info('Parsed %d fuzzers from %s' % (len(all_fuzzers),
                                              fuzzers_directory))
  return all_fuzzers
 

def zip_relevant_corpus(corpus_files, fuzzers):
  """Find relevant corpus files and archive them for every fuzzer given."""
  for fuzzer in fuzzers:
    fuzzer_name = os.path.basename(fuzzer)
    fuzzer_directory = os.path.dirname(fuzzer)
    fuzzer_tags = get_fuzzer_tags(fuzzer_name)
    relevant_corpus_files = set()
    for filename in corpus_files:
      # Remove 'ffmpeg' substring to do not use everything for 'MPEG' codec.
      sanitized_filename = filename.replace('ffmpeg', '').lower()
      for tag in fuzzer_tags:
        if tag in sanitized_filename:
          relevant_corpus_files.add(filename)

      if not relevant_corpus_files:
        # Strip last symbol from tags if we haven't found relevant corpus.
        # It helps for such codecs as 'RV40' ('RV4' -> 'RV') or 'PCX' (-> 'PC').
        for tag in fuzzer_tags:
          if tag[:-1] in sanitized_filename:
            relevant_corpus_files.add(filename)

    logging.info(
        'Found %d relevant samples for %s' % (len(relevant_corpus_files),
                                              fuzzer_name))

    if not relevant_corpus_files:
      continue

    zip_archive_name = fuzzer + "_seed_corpus.zip"
    with zipfile.ZipFile(zip_archive_name, 'w') as archive:
      for filename in relevant_corpus_files:
        archive.write(filename)


def main():
  if len(sys.argv) < 3:
    print('Usage: %s <seed_corpus_directory> <fuzzers_directory>' % __file__)
    sys.exit(1)

  seed_corpus_directory = sys.argv[1]
  fuzzers_directory = sys.argv[2]

  corpus_files = parse_corpus(seed_corpus_directory)
  fuzzers = parse_fuzzers(fuzzers_directory)
  zip_relevant_corpus(corpus_files, fuzzers)


if __name__ == '__main__':
  sys.exit(main())
