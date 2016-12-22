#!/bin/bash

set -e

cd ./build/debian-8/
cp ../../bin/cert-manage-linux cert-manage
docker build -t cert-manage-debian-8:latest . > run.log
docker run -it cert-manage-debian-8:latest $@
cd - > /dev/null
