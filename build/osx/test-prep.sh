#!/bin/bash
set -e

if [[ `uname -s` == 'Darwin' ]];
then
    # Make a request to try and setup the Keychain
    ssid=$(networksetup -getairportnetwork en0 | cut -c 24-)
    if [[ -n "$ssid" || -n "$TRAVIS_OS_NAME" ]];
    then
        set -x
        curl -s -o /dev/null https://google.com
        set +x
    fi
fi
