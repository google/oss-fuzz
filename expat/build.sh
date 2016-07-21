#!/bin/bash -ex

echo $pwd

ls -alR

./buildconf.sh
./configure
