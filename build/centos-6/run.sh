#!/bin/bash

set -e

cd ./build/centos-6/
cp ../../bin/cert-manage-linux cert-manage
docker build -t cert-manage-centos-6:latest . > run.log
docker run -it cert-manage-centos-6:latest $@
cd - > /dev/null
