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
    # ./bin/cert-manage-osx-amd64 -whitelist -file build/osx/whitelist.json
    ./bin/cert-manage-osx-amd64 -list | wc -l # | grep $n

    # Restore
    # TODO(adam): how to test this on travis-ci ??
    # ./bin/cert-manage-osx-amd64 -restore
    # ./bin/cert-manage-osx-amd64 -list | wc -l # | grep $n

    echo "Firefox"
    if [[ -d "/Applications/Firefox.app" ]];
    then
        count=$(./bin/cert-manage-osx-amd64 -list -app firefox | wc -l | tr -d ' ')
        if [[ ! "$count" -gt "1" ]];
        then
            echo "Only found $count firefox certs"
            exit 1
        else
            echo "Found $count firefox certs"
        fi
    fi

    echo "Java"
    if [[ -n "JAVA_HOME" ]];
    then
        count=$(./bin/cert-manage-osx-amd64 -list -app java | wc -l | tr -d ' ')
        if [[ ! "$count" -gt "1" ]];
        then
            echo "Only found $count java certs"
            exit 1
        else
            echo "Found $count java certs"
        fi
    fi

    echo "== END OSX"
fi
