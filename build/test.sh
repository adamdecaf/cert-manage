#!/bin/bash
set -e

# Run OSX ci tests if we're on darwin
if [[ `uname -s` == 'Darwin' ]];
then
    echo "== START OSX"
    version=$(./bin/cert-manage-osx-amd64 -version)
    echo "cert-manage ($version)"

    ./bin/cert-manage-osx-amd64 -list | wc -l
    ./bin/cert-manage-osx-amd64 -backup

    # Whitelist
    mkdir -p build/osx && cp ./testdata/globalsign-whitelist.json build/osx/whitelist.json
    ./bin/cert-manage-osx-amd64 -whitelist -file build/osx/whitelist.json
    ./bin/cert-manage-osx-amd64 -list | wc -l # | grep $n

    # Restore
    # TODO(adam): how to test this on travis-ci ??
    # ./bin/cert-manage-osx-amd64 -restore
    # ./bin/cert-manage-osx-amd64 -list | wc -l # | grep $n
    echo "== END OSX"
fi

# Travis-ci doesn't support docker..
# https://docs.travis-ci.com/user/docker/
if [ "$TRAVIS_OS_NAME" == "osx" ];
then
    echo "TravisCI currently does not support docker on osx, skipping tests"
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
