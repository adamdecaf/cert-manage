#!/bin/bash

set -e

cd ./build/debian-8/
cp ../../bin/cert-manage-linux cert-manage
docker build -t cert-manage-linux:latest . > run.log
docker run -it cert-manage-linux:latest $@
cd - > /dev/null
