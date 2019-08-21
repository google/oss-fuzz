#!/bin/bash

gsutil -h "Cache-Control:no-cache,max-age=0" -m cp -r bower_components index.html src manifest.json gs://oss-fuzz-build-logs
