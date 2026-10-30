#!/bin/bash -eu
# The build lives with the project: .oss-fuzz/build.sh in the mod_pagespeed tree.
exec "$SRC/mod_pagespeed/.oss-fuzz/build.sh"
