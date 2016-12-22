#!/bin/bash

set -e

cd ./build/debian-7/
cp ../../bin/cert-manage-linux cert-manage
docker build -t cert-manage-debian-7:latest . > run.log
docker run -it cert-manage-debian-7:latest $@
cd - > /dev/null
