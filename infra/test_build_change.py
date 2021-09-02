import logging
import sys

import build_and_push_test_images


def main():
  test_image_suffix = sys.argv[1]
  logging.basicConfig(level=logging.DEBUG)
  build_and_push_test_images.build_and_push_images(test_image_suffix)


if __name__ == '__main__':
  main()
