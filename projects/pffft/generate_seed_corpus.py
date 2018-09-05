from __future__ import division
from __future__ import print_function

import os
import sys

import numpy as np

MAX_INPUT_SIZE = int(1e6)
MAX_FLOAT32 = np.finfo(np.float32).max

def IsValidSize(n):
  if n == 0:
    return False
  # PFFFT only supports transforms for inputs of length N of the form
  # N = (2^a)*(3^b)*(5^c) where a >= 5, b >=0, c >= 0.
  FACTORS = [2, 3, 5]
  factorization = [0, 0, 0]
  for i, factor in enumerate(FACTORS):
    while n % factor == 0:
      n = n // factor
      factorization[i] += 1
  return factorization[0] >= 5 and n == 1


def main():
  if len(sys.argv) < 2:
    print('Usage: %s <path to output directory>' % sys.argv[0])
    sys.exit(1)

  output_path = sys.argv[1]
  if not os.path.exists(output_path):
    print('The output path does not exists.')
    sys.exit(2)

  # List of valid input sizes.
  N = [n for n in range(MAX_INPUT_SIZE) if IsValidSize(n)]

  # Set the seed to always generate the same random data.
  np.random.seed(0)

  # Generate different types of input arrays for each target length.
  for n in N:
    # Zeros.
    z = np.zeros(n, np.float32)
    z.tofile(os.path.join(output_path, 'zeros_%d' % n))
    # Max float 32.
    m = np.ones(n, np.float32) * MAX_FLOAT32
    m.tofile(os.path.join(output_path, 'max_%d' % n))
    # Random values in the s16 range.
    rnd_s16 = 32768.0 * 2.0 * (np.random.rand(n) - 1.0)
    rnd_s16 = rnd_s16.astype(np.float32)
    rnd_s16.tofile(os.path.join(output_path, 'rnd_s16_%d' % n))
  
  sys.exit(0)


if __name__ == '__main__':
  main()
