#!/bin/bash

gsutil -m cp -r bower_components index.html src manifest.json gs://oss-fuzz-build-logs
