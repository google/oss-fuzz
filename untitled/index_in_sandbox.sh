#!/bin/sh

# This script is executed inside a sandbox instance when archiving a target.
# It creates necessary symlinks to fix the environment and runs the indexer.

SYSROOT_DIR="$1"
TOYBOX="$2"
INDEXER="$3"
ROOT_DIR="$4"
SOURCE_DIR="$5"
BUILD_DIR="$6"
INDEX_DIR="$7"
OSS_FUZZ_SRC_DIR="$8"

echo "[*]   Called init_instance.sh with parameters:"
echo "      > SYSROOT_DIR: $SYSROOT_DIR"
echo "      > TOYBOX: $TOYBOX"
echo "      > INDEXER: $INDEXER"
echo "      > ROOT_DIR: $ROOT_DIR"
echo "      > SOURCE_DIR: $SOURCE_DIR"
echo "      > BUILD_DIR: $BUILD_DIR"
echo "      > INDEX_DIR: $INDEX_DIR"
echo "      > OSS_FUZZ_SRC_DIR: $OSS_FUZZ_SRC_DIR"

# Function that will only create a symlink if it doesn't already exist.
# Exits in case the symlink path exists but is not a symlink.
add_symlink() {
  target="$1"
  link_name="$2"

  if ! "$TOYBOX" test -L "$link_name"; then
    if "$TOYBOX" test -e "$link_name"; then
      echo "Error: $link_name directory should not exist or be a symlink." >&2
      exit 1
    fi

    echo "[*]   Creating symlink $link_name -> $target"
    if ! "$TOYBOX" ln -s "$target" "$link_name"; then
      echo "[!]    Error: Symlinking $target to $link_name failed" >&2
      exit 1
    fi
  fi
}

# Add symlinks.
add_symlink "$SOURCE_DIR" "$OSS_FUZZ_SRC_DIR"
add_symlink "$ROOT_DIR" "/sysroot"

# Run the indexer.
if ! "$INDEXER" \
  --build_dir="$BUILD_DIR" \
  --index_dir="$INDEX_DIR" \
  --source_dir="$OSS_FUZZ_SRC_DIR" \
  --sysroot_dir="$SYSROOT_DIR"; then
  echo "[!]    Error: Running indexer failed" >&2
  exit 1
fi

echo "[+]    init_instance.sh finished successfully"
exit 0