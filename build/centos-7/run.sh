#!/bin/bash

set -e

cd ./build/centos-7/
cp ../../bin/cert-manage-linux cert-manage
docker build -t cert-manage-centos-7:latest . > run.log
docker run -it cert-manage-centos-7:latest $@
cd - > /dev/null
