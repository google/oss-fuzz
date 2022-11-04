import logging
import sys
import subprocess

def main():
  if len(sys.argv) < 3:
    logging.error('Usage: %s <test_app> <testcase>.', sys.argv[0])
    return 1

  test_app = sys.argv[1]
  return subprocess.run([test_app], check=True).return_code


if __name__ == '__main__':
  sys.exit(main())
