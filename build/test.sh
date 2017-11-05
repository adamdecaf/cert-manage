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
platforms=(alpine-36 debian-8 debian-9 ubuntu-1604 ubuntu-1704)
for plat in "${platforms[@]}"
do
    echo "CI: $plat"
    ./build/"$plat"/test.sh
    if [ ! $? -eq 0 ];
    then
        cat ./build/"$plat"/test.log
        exit 1
    fi
done
