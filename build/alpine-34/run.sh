#!/bin/bash

set -e

cd ./build/alpine-34/
cp ../../bin/cert-manage-linux cert-manage
docker build -t cert-manage-alpine-34:latest . > run.log
docker run -it cert-manage-alpine-34:latest $@
cd - > /dev/null
