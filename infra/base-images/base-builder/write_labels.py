#!/usr/bin/python3

import os
import json
import sys

def main():
  tags = json.loads(sys.argv[1])
  out = sys.argv[2]

  for target_name, labels in tags.items():
    with open(os.path.join(out, target_name + '.labels'), 'w') as f:
      f.write('\n'.join(labels))


if __name__ == '__main__':
  main()
