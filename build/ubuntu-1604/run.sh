#!/bin/bash

set -e

cd ./build/ubuntu-1604/
cp ../../bin/cert-manage-linux cert-manage
docker build -t cert-manage-ubuntu-1604:latest . > run.log
docker run -it cert-manage-ubuntu-1604:latest $@
cd - > /dev/null
