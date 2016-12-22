#!/bin/bash

set -e

cd ./build/ubuntu-1610/
cp ../../bin/cert-manage-linux cert-manage
docker build -t cert-manage-ubuntu-1610:latest . > run.log
docker run -it cert-manage-ubuntu-1610:latest $@
cd - > /dev/null
