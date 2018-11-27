#!/usr/bin/python3

import os
import json
import sys

def main():
  if len(sys.argv) != 3:
    print('Usage: write_labels.py labels_json out_dir', file=sys.stderr)
    sys.exit(1)

  labels_by_target = json.loads(sys.argv[1])
  out = sys.argv[2]

  for target_name, labels in labels_by_target.items():
    with open(os.path.join(out, target_name + '.labels'), 'w') as f:
      f.write('\n'.join(labels))


if __name__ == '__main__':
  main()
