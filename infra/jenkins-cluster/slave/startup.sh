#!/bin/bash -eux

dockerd-entrypoint.sh &

sleep 5

docker version
docker info

jenkins-slave $@
