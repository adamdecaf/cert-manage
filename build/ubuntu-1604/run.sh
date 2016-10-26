#!/bin/bash

set -e

cd ./build/ubuntu-1404/
cp ../../bin/cert-manage-linux cert-manage
docker build -t cert-manage-linux:latest . > run.log
docker run -it cert-manage-linux:latest $@
cd - > /dev/null
