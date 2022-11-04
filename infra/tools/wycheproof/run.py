#!/usr/bin/env python3

import argparse
import os
import sys

def get_args():
  parser = argparse.ArgumentParser()
  parser.add_argument('--input_dir', help='Ignored.',)
  parser.add_argument('--output_dir', help='Directory for writing testcases.', required=True)
  parser.add_argument('--no_of_files', type=int, help='Ignored.')
  return parser.parse_args()

def main():
  args = get_args()
  testcase = os.path.join(args.output_dir, 'testcase')
  with open(testcase, 'w') as file_handle:
    file_handle.write(' ')
  return 0

if __name__ == '__main__':
  sys.exit(main())
