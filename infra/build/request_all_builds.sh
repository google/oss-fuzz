#!/bin/bash

for project in ../../projects/*; do
  if [[ ! -f $project/Dockerfile ]]; then
    continue
  fi

  ./request_build.sh $(basename $project)
done
