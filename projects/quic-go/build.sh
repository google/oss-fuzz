#!/bin/bash

set -euo pipefail

exec bash "$GOPATH/src/github.com/quic-go/quic-go/oss-fuzz.sh" "$@"
