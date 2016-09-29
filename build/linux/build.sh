#!/bin/bash

set -e

cd ./build/linux/
cp ../../cert-manage-linux cert-manage
docker build -t cert-manage-linux:latest .
docker run -it cert-manage-linux:latest $@
cd -
