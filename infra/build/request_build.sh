#!/bin/bash
gcloud pubsub topics publish request-build --message "$1" --project oss-fuzz
