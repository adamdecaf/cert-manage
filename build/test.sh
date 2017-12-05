#!/bin/bash
set -e

local_tests=(osx)
for l in "${local_tests[@]}"
do
    ./build/"$l"/test.sh
done

# Travis-ci doesn't support docker..
# https://docs.travis-ci.com/user/docker/
if [ "$TRAVIS_OS_NAME" == "osx" ];
then
    echo "TravisCI currently does not support docker on osx, skipping docker tests"
    exit 0
fi

# Run each build's tests
platforms=(alpine-3.6 alpine-3.7 debian-8 debian-9 ubuntu-16.04 ubuntu-17.04 ubuntu-17.10)
for plat in "${platforms[@]}"
do
    echo "CI: $plat"
    cd ./build/"$plat"
    cp ../../bin/cert-manage-linux-amd64 cert-manage
    cp ../../testdata/globalsign-whitelist.json whitelist.json
    docker build -t cert-manage:"$plat" . 2>&1 > test.log

    set +e
    docker run -it cert-manage:"$plat" 2>&1 >> test.log
    if [ ! $? -eq 0 ];
    then
        cat test.log
        exit 1
    fi
    set -e

    cd ../../
done
