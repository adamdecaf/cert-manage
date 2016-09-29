#!/bin/bash

set -e

cd ./build/linux/
cp ../../bin/cert-manage-linux cert-manage
docker build -t cert-manage-linux:latest . > build.log
docker run -it cert-manage-linux:latest $@
cd - > /dev/null
